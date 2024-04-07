<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\LoginAttemptService;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

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

    // private function is_Max_Login_Attempts_Exceeded() {
    //     define('MAX_LOGIN_ATTEMPTS', 5);
    //     define('DELAY_DURATION', 300);

    //     // Vérifier si le nombre de tentatives de connexion est défini dans la session
    //     if (!$this->session->has('login_attempts')) {
    //         $this->session->set('login_attempts', 0);
    //     }

    //     // Vérifier si le timestamp de la dernière tentative est défini dans la session
    //     if (!$this->session->has('last_attempt_time')) {
    //         $this->session->set('last_attempt_time', 0);
    //     }

    //     // Vérifier si le délai de 5 minutes s'est écoulé depuis la dernière tentative
    //     if (time() - $this->session->get('last_attempt_time') > DELAY_DURATION) {
    //         // Réinitialiser le nombre de tentatives si le délai est écoulé
    //         $this->session->set('login_attempts', 0);
    //     }

    //     // Incrémenter le nombre de tentatives de connexion
    //     $this->session->set('login_attempts', $this->session->get('login_attempts') + 1);

    //     // Stocker le timestamp de la tentative de connexion actuelle
    //     $this->session->set('last_attempt_time', time());

    //     // Vérifier si le nombre de tentatives de connexion dépasse le maximum
    //     return $this->session->get('login_attempts') > MAX_LOGIN_ATTEMPTS;
    // }

    private function is_valid_password($password) {
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

    #[Route('/register', name: 'register_post', methods: 'POST')]
    public function create(Request $request, UserPasswordHasherInterface $passwordHash): JsonResponse
    {   

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
                case !$this->is_valid_password($userInfo["password"]):
                    return $this->json([
                        'error' => true,
                        'message' => "Le mot de passe doit contenir au moins une majuscule, une minuscule, un chifre, un caractère spécial et avoir 8 caractères minimum"
                    ], 400);
                    break;
            default:
                # code...
                break;
        }

        $user = new User();
        $user->setFirstName($userInfo["firstname"]);
        $user->setlastName($userInfo["firstname"]);
        $user->setEmail($userInfo["firstname"]);
        $user->setIdUser($userInfo["firstname"]);
        $user->setsexe($userInfo["firstname"]);
        $user->setCreateAt(new DateTimeImmutable());
        $user->setUpdateAt(new DateTimeImmutable());
        $password = $userInfo["firstname"];
        $hash = $passwordHash->hashPassword($user, $password); // Hash le password envoyez par l'utilisateur
        $user->setPassword($hash);
        dd($user);
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $this->json([
            'error' => false,
            'message' => "L'utilisateur a bien été vrée avec succès.",
            'user' => $user->serializer(),
        ], 200);
    }

    // use Symfony\Component\HttpFoundation\Request;
    #[Route('/login', name: 'app_login_post', methods: ['POST', 'PUT'])]
    public function login(Request $request, JWTTokenManagerInterface $JWTManager): JsonResponse
    {

        $user = $this->repository->findOneBy(["email" => "User_331"]);

        // $parameters = json_decode($request->getContent(), true);
        parse_str($request->getContent(), $parameters);

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
            case !$this->is_valid_password($parameters["mdp"]):
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