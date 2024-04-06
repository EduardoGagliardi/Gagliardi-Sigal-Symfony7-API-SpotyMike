<?php

namespace App\Controller;

use App\Entity\User;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use PhpParser\JsonDecoder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Serializer\Encoder\JsonDecode;

class LoginController extends AbstractController
{

    private $repository;
    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager){
        $this->entityManager = $entityManager;
        $this->repository = $entityManager->getRepository(User::class);
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

        function is_valid_password($password) {
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

        switch ($user){
            case $user == null:
                return $this->json([
                    'error' => true,
                    'message' => "Le compte n'est plus actif ou est suspendu."
                ], 403);
                break;
            case $parameters["username"] == null || $parameters["mdp"] == null:
                return $this->json([
                    'error' => true,
                    'message' => "Email/password manquants."
                ], 400);
                break;
            case !filter_var($parameters["username"], FILTER_VALIDATE_EMAIL):
                return $this->json([
                    'error' => true,
                    'message' => "Le format de l'email est invalide."
                ], 400);
                break;
            case !is_valid_password($parameters["mdp"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le mot de passe doit contenir au moins une majuscule, une minuscule, un chifre, un caractère spécial et avoir 8 caractères minimum"
                ], 400);
                break;
                /*
                case true:
                    return $this->json([
                        'error' => true,
                        'message' => "Trop de tentatives de connexion (5 max). Veuillez réessayer ultérieurerment - xxx min d'attente"
                    ], 429);
                    break;
                */
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