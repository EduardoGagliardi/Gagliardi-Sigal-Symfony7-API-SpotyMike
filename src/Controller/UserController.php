<?php

namespace App\Controller;

use App\Entity\User;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Security\Authentication\Token\PreAuthenticationJWTUserToken;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWSProvider\JWSProviderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\Serializer\Serializer;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserController extends AbstractController
{
    private $repository;
    private $tokenVerifier;
    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager, TokenVerifierService $tokenVerifier){
        $this->entityManager = $entityManager;
        $this->tokenVerifier = $tokenVerifier;
        $this->repository = $entityManager->getRepository(User::class);
    }

    #[Route('/user', name: 'user_post', methods: 'POST')]
    public function create(Request $request): JsonResponse{
        parse_str($request->getContent(), $parametres);

        $TokenVerif = $this->tokenVerifier->checkToken($request);
        if(gettype($TokenVerif) == 'boolean'){
            return $this->json($this->tokenVerifier->sendJsonErrorToken($TokenVerif),401);
        }
        $user = $TokenVerif;

        switch ($user) {
            case !preg_match("#^(\+33|0)[67][0-9]{8}$#", $parametres["tel"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le format du numéro de téléphone est invalide."
                ], 400);
                break;
            case $parametres["sexe"] !== 1 && $parametres["sexe"] !== 0:
                return $this->json([
                    'error' => true,
                    'message' => "La valeur du champ sexe est invalide. Les valeurs autorisées sont 0 pour Femme, 1 pour Homme."
                ], 400);
                break;
            case $this->CheckRequestPost($request):
                return $this->json([
                    'error' => true,
                    'message' => "Les données fournies sont invalides ou incomplètes."
                ], 400);
                break;
            case $this->loginAttemptService->isBlocked($user->getEmail(), false):
                return $this->json([
                    'error' => true,
                'message' => "Authentification requise. vous devez êtres connecté pour effectuer cette action."
                ], 401);    
                break;
            case $this->isNumberUsed($parametres["tel"]):
                return $this->json([
                    'error' => true,
                    'message' => "Conflit de données. Le numéro de téléphone est déjà utilisé par un autre utilisateur."
                ], 401  );
                break;
            default:
            try {
                $utilisateur = $this->entityManager->getRepository(User::class)->find($user->getId());
                if($parametres["firstname"] != null){
                    $utilisateur->setFirstName($parametres["firstname"]);
                }
                if($parametres["lastname"] != null){
                    $utilisateur->setLastName($parametres["lastname"]);
                }
                if($parametres["tel"] != null){
                    $utilisateur->setTel($parametres["tel"]);
                }
                if($parametres["sexe"] != null){
                    $utilisateur->setSexe($parametres["sexe"]);
                }
                $this->entityManager->flush();
                return $this->json([
                    'error' => false,
                    'message' => "Votre inscription a bien été prise en compte",
                ], 200);
            } 
            catch (\Doctrine\DBAL\Exception $e) {
                return $this->json([
                    'error' => true,
                    'message' => "Erreur de validation des données.",
                ], 422);
            }
                break;
        }
    }

    #[Route('/user', name: 'user_put', methods: 'PUT')]
    public function update(Request $request): JsonResponse
    {

        $dataMiddellware = $this->tokenVerifier->checkToken($request);
        if(gettype($dataMiddellware) == 'boolean'){
            return $this->json($this->tokenVerifier->sendJsonErrorToken($dataMiddellware));
        }
        $user = $dataMiddellware;

        dd($user);
        $phone = "0668000000";
        if(preg_match("/^[0-9]{10}$/", $phone)) {
            $old = $user->getTel();
            $user->setTel($phone);
            $this->entityManager->flush();
            return $this->json([
                "New_tel" => $user->getTel(),
                "Old_tel" => $old,
                "user" => $user->serializer(),
            ]);
        }
    }

    #[Route('/user', name: 'user_delete', methods: 'DELETE')]
    public function delete(): JsonResponse
    {
        $this->entityManager->remove($this->repository->findOneBy(["id"=>1]));
        $this->entityManager->flush();
        return $this->json([
            'message' => 'Welcome to your new controller!',
            'path' => 'src/Controller/UserController.php',
        ]);
    }

    #[Route('/user', name: 'user_get', methods: 'GET')]
    public function read(): JsonResponse
    {


        $serializer = new Serializer([new ObjectNormalizer()]);
        // $jsonContent = $serializer->serialize($person, 'json');
        return $this->json([
            'message' => 'Welcome to your new controller!',
            'path' => 'src/Controller/UserController.php',
        ]);
    }

    #[Route('/user/all', name: 'user_get_all', methods: 'GET')]
    public function readAll(): JsonResponse
    {
        $result = [];

        try {
            if (count($users = $this->repository->findAll()) > 0)
                foreach ($users as $user) {
                    array_push($result, $user->serializer());
                }
            return new JsonResponse([
                'data' => $result,
                'message' => 'Successful'
            ], 200);
        } catch (\Exception $exception) {
            return new JsonResponse([
                'message' => $exception->getMessage()
            ], 404);
        }
    }
}
