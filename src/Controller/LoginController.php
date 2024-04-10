<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\LoginAttemptService;
use DateTime;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Validator\Validator\ValidatorInterface;

class LoginController extends AbstractController
{
    private $loginAttemptService;
    private $repository;
    private $entityManager;

    public function __construct(LoginAttemptService $loginAttemptService, EntityManagerInterface $entityManager){
        $this->entityManager = $entityManager;
        $this->repository = $entityManager->getRepository(User::class);
        $this->loginAttemptService = $loginAttemptService;
    }

    private function isDateFormatValid(ValidatorInterface $validator, $dateString){
        $errors = $validator->validate($dateString, [
            new \Symfony\Component\Validator\Constraints\Date(['format' => 'd/m/Y']),
        ]);

        return count($errors) === 0;
    }

    private function isValidPassword($password) {
        // Vérifie si le mot de passe contient au moins une majuscule
        if (!preg_match('/[A-Z]/', $password)) {
            return false;
        }
        
        // Vérifie si le mot de passe contient au moins une minuscule
        if (!preg_match('/[a-z]/', $password)) {
            return false;
        }
        
        // Vérifie si le mot de passe contient au moins un chiffre
        if (!preg_match('/[0-9]/', $password)) {
            return false;
        }
        
        // Vérifie si le mot de passe contient au moins un caractère spécial
        if (!preg_match('/[!@#$%^&*()-_=+{};:,<.>]/', $password)) {
            return false;
        }
        
        // Vérifie si le mot de passe a une longueur d'au moins 8 caractères
        if (strlen($password) < 8) {
            return false;
        }
        
        return true;
    }

    private function isUserOverAge($birthdateString){
        $birthdate = new DateTime($birthdateString);
        $today = new DateTime();
        $age = $today->diff($birthdate)->y;

        return $age >= 12;
    }

    private function isEmailUsed($email){
        
        $user = $this->repository->findOneBy(["email" => $email]);

        if ($user == null){
            return false;
        }
        return true;
    }

    #[Route('/register', name: 'register_post', methods: 'POST')]
    public function create(Request $request, UserPasswordHasherInterface $passwordHash,ValidatorInterface $validator): JsonResponse{   

        parse_str($request->getContent(), $userInfo);

        switch ($userInfo) {
            case $userInfo["firstname"] == null || $userInfo["lastname"] == null || $userInfo["email"] == null || $userInfo["password"] == null || $userInfo["datebirth"] == null:
                return $this->json([
                    'error' => true,
                    'message' => "Des champs obligatoires sont manquants."
                ], 400);
                break;
            case !filter_var($userInfo["email"], FILTER_VALIDATE_EMAIL):
                return $this->json([
                    'error' => true,
                    'message' => "Le format de l'email est invalide."
                ], 400);
                break;
            case !$this->isValidPassword($userInfo["password"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le mot de passe doit contenir au moins une majuscule, une minuscule, un chifre, un caractère spécial et avoir 8 caractères minimum"
                ], 400);
                break;
            case !$this->isDateFormatValid($validator, $userInfo["datebirth"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le format de la date de naissance et invalide. Le format attendu est JJ/MM/AAAA."
                ], 400);
                break;
            case !$this->isUserOverAge($userInfo["datebirth"]):
                return $this->json([
                    'error' => true,
                    'message' => "L'utilisateur doit avoir au moins 12 ans."
                ], 400);
                break;
            case!preg_match("#^(\+33|0)[67][0-9]{8}$#", $userInfo["tel"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le format du numéro de téléphone est invalide."
                ], 400);
                break;
            case !$userInfo["sexe"] == 1 || !$userInfo["sexe"] == 0:
                return $this->json([
                    'error' => true,
                    'message' => "La valeur du champ sexe est invalide. Les valeurs autorisées sont 0 pour Femme, 1 pour Homme."
                ], 400);
                break;
            case !$userInfo["sexe"] == 1 || !$userInfo["sexe"] == 0:
                return $this->json([
                    'error' => true,
                    'message' => "Cet email est déjà utilisé par un autre compte."
                ], 409);
                break;
            default:
                $user = new User();
                $user->setFirstName($userInfo["firstname"]);
                $user->setlastName($userInfo["lastname"]);
                $user->setEmail($userInfo["emai"]);
                $user->setIdUser("User_".rand(0,999));
                $user->setsexe($userInfo["sexe"]);
                $user->setDateBirth($userInfo["datebirth"]);
                $user->setCreateAt(new DateTimeImmutable());
                $user->setUpdateAt(new DateTimeImmutable());
                $password = $userInfo["password"];
                $hash = $passwordHash->hashPassword($user, $password); // Hash le password envoyez par l'utilisateur
                $user->setPassword($hash);
                dd($user);
                $this->entityManager->persist($user);
                $this->entityManager->flush();
        
                return $this->json([
                    'error' => false,
                    'message' => "L'utilisateur a bien été vrée avec succès.",
                    'user' => $user->serializer(),
                ], 201);
                break;
        }
    }

    // use Symfony\Component\HttpFoundation\Request;
    #[Route('/login', name: 'app_login_post', methods: ['POST', 'PUT'])]
    public function login(Request $request, JWTTokenManagerInterface $JWTManager): JsonResponse{

        // $parameters = json_decode($request->getContent(), true);
        parse_str($request->getContent(), $parameters);

        $user = $this->repository->findOneBy(["email" => $parameters["email"]]);

        switch ($parameters){
            case $user == null:
                return $this->json([
                    'error' => true,
                    'message' => "Le compte n'est plus actif ou est suspendu."
                ], 403);
                break;
            case $parameters["username"] === null || $parameters["mdp"] === null:
                return $this->json([
                    'error' => true,
                    'message' => "Email/password manquants."
                ], 400);
                break;
            case !$this->isValidPassword($parameters["mdp"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le mot de passe doit contenir au moins une majuscule, une minuscule, un chifre, un caractère spécial et avoir 8 caractères minimum"
                ], 400);
                break;
            default:
            case $this->loginAttemptService->isBlocked($parameters["username"]):
                $remainingTime = $this->loginAttemptService->getRemainingPenaltyTime($parameters["username"]);
                $minutes = ceil($remainingTime / 60);
                return $this->json([
                    'error' => true,
                    'message' => "Trop de tentatives de connexion (5 max). Veuillez réessayer ultérieurement - $minutes min d'attente"
                ], 429);
                break;
            dd(false);
                return $this->json([
                    'error' => false,
                    'message' => "L'utilisateur à été authentifié succès",
                    'user' => $user,
                    'token' => $JWTManager->create($user),
                ], 200);
                break;
        }
    }
}