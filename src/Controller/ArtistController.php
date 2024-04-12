<?php

namespace App\Controller;

use App\DataFixtures\User;
use App\Service\LoginAttemptService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;

class ArtistController extends AbstractController
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

    #[Route('/account-deactivation', name: 'user_delete', methods: 'DELETE')]
    public function Delete(Request $request):JsonResponse{
    parse_str($request->getContent(), $parametres);

        $TokenVerif = $this->tokenVerifier->checkToken($request);
        if(gettype($TokenVerif) == 'boolean'){
            return $this->json($this->tokenVerifier->sendJsonErrorToken($TokenVerif),401);
        }
        $user = $TokenVerif;
        switch ($user) {
            case $user->getStatut() == false:
                return $this->json([
                    'error' => true,
                    'message' => 'Le compte est déjà désactivé.'
                ], 409);
                break;
            default:
                $utilisateur = $this->entityManager->getRepository(User::class)->find($user->getId());
                $utilisateur->setStatut(false);
                $this->entityManager->flush();
                return $this->json([
                    'error' => false,
                    'message' => "Votre compte a été désactivé avec succés. Nous sommes désolés de vous voir partir."
                ], 200);
                break;
        }
    }
}