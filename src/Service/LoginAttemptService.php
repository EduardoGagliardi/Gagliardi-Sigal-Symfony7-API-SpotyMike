<?php

namespace App\Service;

use App\Entity\LoginAttempt;
use DateTime;
use Doctrine\ORM\EntityManagerInterface;

class LoginAttemptService
{
    private const MAX_ATTEMPTS = 5;
    private const PENALTY_DURATION = 300; // 5 minutes en secondes

    private $entityManager;

    public function __construct(EntityManagerInterface $entityManager)
    {
        $this->entityManager = $entityManager;
    }

    public function isBlocked(string $email): bool
    {
        $loginAttemptRepository = $this->entityManager->getRepository(LoginAttempt::class);

        // Récupérer la dernière tentative de connexion
        $lastAttempt = $loginAttemptRepository->findOneBy(['email' => $email], ['attemptedAt' => 'DESC']);

        if (!$lastAttempt) {
            // Créer un nouvel enregistrement s'il n'existe pas
            $lastAttempt = new LoginAttempt();
            $lastAttempt->setEmail($email);
            $lastAttempt->setAttempt(1); // Premier essai
            $lastAttempt->setDate(new DateTime());
            $this->entityManager->persist($lastAttempt);
        }
        $currentTime = new DateTime();
        $penaltyEnd = $lastAttempt->getdate()->getTimestamp() + self::PENALTY_DURATION;
        if ($currentTime->getTimestamp() > $penaltyEnd) {
            // Si plus de 5 minutes se sont écoulées depuis la dernière tentative, réinitialiser le compteur d'essais
            $lastAttempt->setAttempt(0);
            $this->entityManager->persist($lastAttempt);
            $this->entityManager->flush();
            return false;
        }else {

            // Mettre à jour le compteur d'essais
            $lastAttempt->setAttempt($lastAttempt->getAttempt() + 1);
            $this->entityManager->persist($lastAttempt);
        }

        // Mettre à jour la date de la dernière tentative
        $lastAttempt->setDate(new DateTime());
        $this->entityManager->flush();

        // Vérifier si l'utilisateur est bloqué
        if ($lastAttempt->getAttempt() >= self::MAX_ATTEMPTS) {
            $currentTime = new DateTime();
            $penaltyEnd = $lastAttempt->getdate()->getTimestamp() + self::PENALTY_DURATION;
            if ($currentTime->getTimestamp() < $penaltyEnd) {
                return true; // Utilisateur bloqué temporairement
            } else {
                // Réinitialiser les tentatives après la période de pénalité
                $lastAttempt->setAttempt(0);
                $this->entityManager->persist($lastAttempt);
                $this->entityManager->flush();
            }
        }

        return false; // Utilisateur non bloqué
    }

    public function getRemainingPenaltyTime(string $email): int
    {
        $loginAttemptRepository = $this->entityManager->getRepository(LoginAttempt::class);

        // Récupérer la dernière tentative de connexion
        $lastAttempt = $loginAttemptRepository->findOneBy(['email' => $email], ['attemptedAt' => 'DESC']);

        if (!$lastAttempt) {
            return 0; // Pas de tentative précédente
        }

        $currentTime = new DateTime();
        $penaltyEnd = $lastAttempt->getdate()->getTimestamp() + self::PENALTY_DURATION;
        $remainingTime = $penaltyEnd - $currentTime->getTimestamp();

        return max($remainingTime, 0); // Retourne le temps restant ou 0 si pas en pénalité
    }
}