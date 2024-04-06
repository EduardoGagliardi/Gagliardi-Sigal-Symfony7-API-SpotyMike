<?php

namespace App\Controller;

use App\Entity\User;
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

    private $repository;
    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager){
        $this->entityManager = $entityManager;
        $this->repository = $entityManager->getRepository(User::class);
    }

    #[Route('/login/register', name: 'user_post', methods: 'POST')]
    public function create(Request $request, UserPasswordHasherInterface $passwordHash): JsonResponse
    {

        $user = new User();
        $user->setFirstName("Mike");
        $user->setlastName("Mike");
        $user->setEmail("mike.sylvestre@lyknowledge.io");
        $user->setIdUser("Mike");
        $user->setsexe(1);
        $user->setCreateAt(new DateTimeImmutable());
        $user->setUpdateAt(new DateTimeImmutable());
        $password = "Mike";
        $hash = $passwordHash->hashPassword($user, $password); // Hash le password envoyez par l'utilisateur
        $user->setPassword($hash);
        dd($user);
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $this->json([
            'isNotGoodPassword' => ($passwordHash->isPasswordValid($user, 'Zoubida') ),
            'isGoodPassword' => ($passwordHash->isPasswordValid($user, $password) ),
            'user' => $user->serializer(),
            'path' => 'src/Controller/UserController.php',
        ]);
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