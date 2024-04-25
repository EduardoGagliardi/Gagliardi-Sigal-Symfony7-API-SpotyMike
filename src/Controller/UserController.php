<?php

namespace App\Controller;

use App\Entity\User;
use DateTimeImmutable;
use Doctrine\ORM\EntityManagerInterface;
use App\Controller\TokenVerifierService;
use App\Service\LoginAttemptService;
use DateTime;
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
    private $loginAttemptService;

    public function __construct(LoginAttemptService $loginAttemptService, EntityManagerInterface $entityManager, TokenVerifierService $tokenVerifier){
        $this->entityManager = $entityManager;
        $this->tokenVerifier = $tokenVerifier;
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

    private function isNumberUsed($num){
        $user = $this->repository->findOneBy(["tel" => $num]);

        if ($user == null){
            return false;
        }
        return true;
    }

    private function CheckRequestPost($request){

        parse_str($request->getContent(), $parametres);
            // Obtenez les clés des données envoyées dans la requête POST
        $keys = $request->request->keys();

        // Vérifiez si les clés attendues sont présentes
        $expectedKeys = ['firstname', 'lastname', 'tel', 'sexe'];
        $missingKeys = array_diff($expectedKeys, $keys);
        
        if($parametres["firstname"] == null && $parametres["lastname"] == null && $parametres["tel"] == null && $parametres["sexe"] == null){
            return true;
        }
        else if(!empty($missingKeys)){
            return true;
        }
        else if(strlen($parametres["firstname"])> 60){
            return true;
        } 
        else if(strlen($parametres["lastname"])> 60){
            return true;
        }
        else if(count($parametres["tel"]) !== 10){
            return true;
        }
        else if(intval($parametres["sexe"]) !== 0 or 1){
            return true;
        }
        return false;
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

    #[Route('/account-deactivation', name: 'user_delete', methods: 'DELETE')]
    public function delete(Request $request): JsonResponse{
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

    #[Route('/user', name: 'user_get', methods: 'GET')]
    public function read(Request $request): JsonResponse{
        $TokenVerif = $this->tokenVerifier->checkToken($request);
        if(gettype($TokenVerif) == 'boolean'){
            return $this->json($this->tokenVerifier->sendJsonErrorToken($TokenVerif),401);
        }
        $user = $TokenVerif;
        $utilisateur = $this->entityManager->getRepository(User::class)->find($user->getId());
        return $this->json([
            'data' => $utilisateur->serializer(),
        ], 200);
    }

    #[Route('/user/all', name: 'user_get_all', methods: 'GET')]
    public function readAll(): JsonResponse{
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
