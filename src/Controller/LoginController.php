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

    private function isDateFormatValid($dateString){
        // Vérifier la longueur de la chaîne de date
        if(strlen($dateString) !== 10) {
            return false; // La longueur de la chaîne de date ne correspond pas à 'jj/mm/aaaa'
        }

        // Vérifier le format de la chaîne de date
        if(preg_match("#^\d{2}/\d{2}/\d{4}$#", $dateString) !== 1) {
            return false; // Le format de la chaîne de date est incorrect
        }

        // Vérifier les détails de la date
        $dateParts = explode('/', $dateString);
        $day = (int)$dateParts[0];
        $month = (int)$dateParts[1];
        $year = (int)$dateParts[2];

        if(!checkdate($month, $day, $year)) {
            return false; // La date est invalide
        }

        return true; // La chaîne de date est valide
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
        // Extraction du jour, mois et année à partir de la chaîne de date de naissance
        list($day, $month, $year) = explode('/', $birthdateString);

        // Création d'un objet DateTime à partir de la chaîne de date de naissance
        $birthdate = new DateTime("$year-$month-$day");

        // Création d'un objet DateTime représentant la date d'aujourd'hui
        $today = new DateTime();

        // Calcul de la différence entre la date d'aujourd'hui et la date de naissance pour obtenir l'âge
        $age = $today->diff($birthdate)->y;

        // Vérification si l'âge est supérieur ou égal à 12 ans
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
    public function create(Request $request, UserPasswordHasherInterface $passwordHash): JsonResponse{   

        parse_str($request->getContent(), $userInfo);
        $userInfo["sexe"] = intval($userInfo["sexe"]);
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
            case !$this->isDateFormatValid($userInfo["datebirth"]):
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
            case !preg_match("#^(\+33|0)[67][0-9]{8}$#", $userInfo["tel"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le format du numéro de téléphone est invalide."
                ], 400);
                break;
            case $userInfo["sexe"] !== 1 && $userInfo["sexe"] !== 0:
                return $this->json([
                    'error' => true,
                    'message' => "La valeur du champ sexe est invalide. Les valeurs autorisées sont 0 pour Femme, 1 pour Homme."
                ], 400);
                break;
            case $this->isEmailUsed($userInfo["email"]):
                return $this->json([
                    'error' => true,
                    'message' => "Cet email est déjà utilisé par un autre compte."
                ], 409);
                break;
            default:
            
                $date = DateTime::createFromFormat('d/m/Y', $userInfo["datebirth"]);
                $user = new User();
                $user->setFirstName($userInfo["firstname"]);
                $user->setlastName($userInfo["lastname"]);
                $user->setEmail($userInfo["email"]);
                $user->setIdUser("User_".rand(0,999999));
                $user->setsexe($userInfo["sexe"]);
                $user->setTel($userInfo["tel"]);
                $user->setDateBirth($date);
                $user->setCreateAt(new DateTimeImmutable());
                $user->setUpdateAt(new DateTimeImmutable());
                $password = $userInfo["password"];
                $hash = $passwordHash->hashPassword($user, $password);
                $user->setPassword($hash);
                $this->entityManager->persist($user);
                $this->entityManager->flush();

                return $this->json([
                    'error' => false,
                    'message' => "L'utilisateur a bien été crée avec succès.",
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
            case $parameters["email"] === null || $parameters["mdp"] === null:
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
            case $this->loginAttemptService->isBlocked($parameters["email"], false):
                $remainingTime = $this->loginAttemptService->getRemainingPenaltyTime($parameters["email"]);
                $minutes = ceil($remainingTime / 60);
                return $this->json([
                    'error' => true,
                    'message' => "Trop de tentatives de connexion (5 max). Veuillez réessayer ultérieurement - $minutes min d'attente."
                ], 429);
                break;
            default:
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