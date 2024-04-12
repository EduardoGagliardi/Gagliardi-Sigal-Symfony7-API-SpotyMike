<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\LoginAttemptService;
use App\Controller\TokenVerifierService;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWSProvider\JWSProviderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

class PasswordController extends AbstractController
{
    private $repository;
    private $tokenVerifier;
    private $entityManager;
    private $loginAttemptService;
    private $jwtProvider;
    private $jwtManager;
    private $userRepository;

    public function __construct(JWTTokenManagerInterface $jwtManager, UserRepository $userRepository, JWSProviderInterface $jwtProvider, LoginAttemptService $loginAttemptService,EntityManagerInterface $entityManager,  TokenVerifierService $tokenVerifier) {
        $this->entityManager = $entityManager;
        $this->jwtManager = $jwtManager;
        $this->tokenVerifier = $tokenVerifier;
        $this->jwtProvider = $jwtProvider;
        $this->userRepository = $userRepository;
        $this->loginAttemptService = $loginAttemptService;
        $this->repository = $entityManager->getRepository(User::class);
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

    private function checkToken($token){
        $dataToken = $this->jwtProvider->load($token);
            if($dataToken->isVerified($token)){
                return false;
            }
        return true;
    }

    #[Route('/password-lost', name:'password_Lost', methods: ['POST'])]
    public function createResetToken(Request $request, JWTTokenManagerInterface $JWTManager): JsonResponse{
        parse_str($request->getContent(), $parametres);
        $user = $this->repository->findOneBy(["email" => $parametres["email"]]);

        switch ($parametres){
            case $user == null:
                return $this->json([
                    'error' => true,
                    'message' => "Aucune compte n'est associé à cet email. Veuillez vérifier et réessayer."
                ], 404);
                break;
            case $parametres["email"] == null:
                return $this->json([
                    'error' => true,
                    'message' => "Email manquant. Vuillez fournir votre email pour la récupération du mot de passe."
                ], 400);
                break;
            case $this->loginAttemptService->isBlocked($parametres["email"], true):

                $remainingTime = $this->loginAttemptService->getRemainingPenaltyTime($parametres["email"]);
                $minutes = ceil($remainingTime / 60);

                return $this->json([
                    'error' => true,
                    'message' => "Trop de tentatives de connexion (3 max). Veuillez réessayer ultérieurement - $minutes min d'attente."
                ], 429);
                break;
            case !filter_var($parametres["email"], FILTER_VALIDATE_EMAIL):
                return $this->json([
                    'error' => true,
                    'message' => "Le format de l'email est invalide."
                ], 400);
                break;
            default:
                $payload = [
                    'email' => $user->getEmail(),
                    'exp' => time() + 120 // 2 minutes * 60 secondes
                ];
                return $this->json([
                    'success' => true,
                    'message' => "Un email de réinitialistion de mot de passe a été envoyé à votre adresse email. Veuillez suivre les instructions contenues dans l'email pour réinitialiser votre mot de passe",
                    'token' => $JWTManager->create($user)
                ], 200);
                break;
        }
    }

    #[Route('/reset-password/{token}', name: 'reset_password', methods: 'GET')]
    public function resetPassword(Request $request, TokenVerifierService $tokenVerifier, JWTTokenManagerInterface $JWTManager, string $token): JsonResponse{

        parse_str($request->getContent(), $parametres);
        $dataToken = $this->jwtProvider->load($token);
        $email = $dataToken->getPayload()['username'];
        switch ($token){
            case $token == null:
                return $this->json([
                    'error' => true,
                    'message' => "Token de réinitialisation manquant ou invalide, Veuillez utilisé"
                ], 400);
                break;
            case $parametres["password"] == null:
                //mdp menquant
                return $this->json([
                    'error' => true,
                    'message' => "veuiller fournir un nouveau mot de passe."
                ], 400);
                break;
            case !$this->isValidPassword($parametres["password"]):
                //format mdp invalide
                return $this->json([
                    'error' => true,
                    'message' => "Le nouveau mot de passe ne respecte pas les critères requis. Il doit contenir au moins une majuscule, une minuscule, un chifre, un caractère spécial et être composé d'au moins 8 caractères."
                ], 400);
                break;
            case $this->checkToken($token):
                return $this->json([
                    'error' => true,
                    'message' => "Votre token de réinitialisation de mot de passe a éxpiré. Veuillez refaire une demande de réinitialisation de mot de passe."
                ], 410);
                //token expiré
                break;
            default:

            $utilisateur = $this->entityManager->getRepository(User::class)->findOneBy(["email" => $email]);
            $utilisateur->setPassword($parametres["password"]);
            $this->entityManager->flush();
                return $this->json([
                    'success' => true,
                    'message' => "Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter avec votre nouveau mot de passe."
                ], 200);
                break;
        }
    }
}