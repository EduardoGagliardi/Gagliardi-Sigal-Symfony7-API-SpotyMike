<?php

namespace App\Controller;

use App\Entity\User;
use App\Service\LoginAttemptService;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Validator\Constraints\IsFalse;
use Symfony\Component\Validator\Constraints\IsNull;

class PasswordController extends AbstractController
{
    private $repository;
    private $tokenVerifier;
    private $entityManager;
    private $loginAttemptService;

    public function __construct(LoginAttemptService $loginAttemptService, EntityManagerInterface $entityManager, TokenVerifierService $tokenVerifier){
        $this->entityManager = $entityManager;
        $this->tokenVerifier = $tokenVerifier;
        $this->repository = $entityManager->getRepository(User::class);
        $this->loginAttemptService = $loginAttemptService;
    } 

    #[Route('/password-lost', name: 'password_Lost', methods: 'post')]
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
                return $this->json([
                    'error' => False,
                    'message' => "Un email de réinitialistion de mot de passe a été envoyé à votre adresse email. Veuillez suivre les instructions contenues dans l'email pour réinitialiser votre mot de passe",
                    'token' => $JWTManager->create($user)
                ], 200);
                break;
        }
    }
}