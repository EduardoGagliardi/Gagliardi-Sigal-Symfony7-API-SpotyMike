<?php

namespace App\Controller;

use App\Entity\Artist;
use App\Entity\User;
use App\Service\LoginAttemptService;
use DateTime;
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

    private function isnameTaken($fullname){
        $artist = $this->repository->findOneBy(['fullname' => $fullname]);
        if($artist != null){
            return true;
        }
        return false;
    }

    // #[Route('/account-deactivation', name: 'user_delete', methods: 'DELETE')]
    // public function Delete(Request $request):JsonResponse{
    //     parse_str($request->getContent(), $parametres);

    //     $TokenVerif = $this->tokenVerifier->checkToken($request);
    //     if(gettype($TokenVerif) == 'boolean'){
    //         return $this->json($this->tokenVerifier->sendJsonErrorToken($TokenVerif),401);
    //     }
    //     $user = $TokenVerif;
    //     $parametres["sexe"] = intval($parametres["sexe"]);

    //     $TokenVerif = $this->tokenVerifier->checkToken($request);
    //     if(gettype($TokenVerif) == 'boolean'){
    //         return $this->json($this->tokenVerifier->sendJsonErrorToken($TokenVerif),401);
    //     }
    //     $user = $TokenVerif;
    //     switch ($user) {
    //         case $user->getStatut() == false:
    //             return $this->json([
    //                 'error' => true,
    //                 'message' => 'Le compte est déjà désactivé.'
    //             ], 409);
    //             break;
    //         default:
    //             $utilisateur = $this->entityManager->getRepository(User::class)->find($user->getId());
    //             $utilisateur->setStatut(false);
    //             $this->entityManager->flush();
    //             return $this->json([
    //                 'error' => false,
    //                 'message' => "Votre compte a été désactivé avec succés. Nous sommes désolés de vous voir partir."
    //             ], 200);
    //             break;
    //     }
    // }
    #[Route('/artist', name: 'create_artist', methods: 'POST')]
    public function create(Request $request):JsonResponse{

        parse_str($request->getContent(), $parametres);
        //on vérifie le token et on récupère user du token
        $TokenVerif = $this->tokenVerifier->checkToken($request);
        if(gettype($TokenVerif) == 'boolean'){
            return $this->json($this->tokenVerifier->sendJsonErrorToken($TokenVerif),401);
        }
        $user = $TokenVerif;

        $parameters = $request->getContent();
        parse_str($parameters, $data);
        $explodeData = explode(",", $data['avatar']);
        $base64Data = $data['avatar'];
        list($type, $base64Data) = explode(';', $base64Data);
        list(, $base64Data)      = explode(',', $base64Data);
        $extension = "";
        if('data:image/jpeg'){
            $extension = 'jpg';
        }
        else if('data:image/png'){
            $extension = 'png';
        }
        // Decode the base64 data
        $imageData = base64_decode($base64Data);

        if($imageData == null){
            return $this->json([
                'error' => true,
                'message' => "Le serveur ne peut pas décoder le contenue base64 en fichier binaire."
            ], 422);
        }
        $fileSize = strlen($imageData);
        if ($fileSize < 1048576 || $fileSize > 7340032) {
            return $this->json([
                'error' => true,
                'message' => "Le fichier envoyé est trop ou pas assez volumineux. vous devez respecter la taille entre 1Mb et 7Mb."
            ], 422);
        }

        $chemin = $this->getParameter('upload_directory') . '/' . $user->getIdUser();
        // Define the file path to save the image
        $filePath = $chemin . "/avatar." . $extension;

        if (!file_exists($chemin)) {
            mkdir($chemin);
        }
        if ($extension == "png") {
            file_put_contents($filePath, $imageData);
        }
        else if ($extension == "jpg") {
            file_put_contents($filePath, $imageData);
        }
        else {
            return $this->json([
                'error' => true,
                'message' => "Erreur sur le format du fichier qui est n'est pas pris en compte."
            ], 422);
        }

        //on récupère la diférance d'age
        $dateString = $user->getDateBirth();
        $format = 'Y-m-d'; 
        $dateOfBirth = new DateTime($dateString);
        $dateOfBirth->format('Y-m-d H:i:s');
        $currentDate = new DateTime(); 
        $age = $currentDate->diff($dateOfBirth)->y;

        switch ($parametres) {
            case $parametres["label"] == null || $parametres["fullname"] == null:
                return $this->json([
                    'error' => true,
                    'message' => "L'id du label et le fullname sont obligatoires."
                ],400);
                break;
            case preg_match('/[!@#$%^&*()-_=+{};:",<.>]/',$parametres["label"]):
                return $this->json([
                    'error' => true,
                    'message' => "Le format de l'id du label est invalide"
                ]);
                break;
            case $age < 16:
                return $this->json([
                    'error' => true,
                    'message' => "Vous devez avoir au moins 16 ans pour être artiste."
                ], 403);
                break;
            case $this->isnameTaken($parameters["fullname"]):
                return $this->json([
                    'error' => true,
                    'message' => "Ce nom d'artiste est déjà pris. Veuillez en choisir un autre."
                ], 409);
                break;
            default:
            $artiste = new Artist;
            $artiste->setLabel($parametres["label"]);
            $artiste->setFullname($parametres["fullname"]);
            $artiste->setDescription($parametres["description"]);
            $artiste->setUserId($user);
            dd($artiste);
                return $this->json([
                    'success' => true,
                    'message' => "Votre compte d'artiste a été créé avec succès. Bienvenue dans notre communauté d'artistes!",
                    'artist_id' => $artiste->getid()
                ], 200);
                break;
        }
    }
}