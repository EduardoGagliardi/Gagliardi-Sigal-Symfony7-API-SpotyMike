<?php

namespace App\Entity;

use DateTime;
use Doctrine\ORM\Mapping as ORM;
use App\Repository\LoginAttemptRepository;

#[ORM\Entity]
class LoginAttempt
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\Column(length: 55)]
    private ?string $email = null;

    #[ORM\Column]
    private ?int $attempted = null;

    #[ORM\Column]
    private ?DateTime $attemptedAt = null;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    public function getAttempt(): ?int
    {
        return $this->attempted;
    }

    public function setAttempt(int $attempted): static
    {
        $this->attempted = $attempted;

        return $this;
    }

    public function getDate(): ?DateTime
    {
        return $this->attemptedAt;
    }

    public function setDate(DateTime $date): static
    {
        $this->attemptedAt = $date;

        return $this;
    }
    
    public function serializer()
    {
        return [
            "id" => $this->getId(),
            "email" => $this->getEmail(),
            "attempt" => $this->getAttempt(),
            "attemptAt" => $this->getdate()
        ];
    }

}