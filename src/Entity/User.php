<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use App\Repository\UserRepository;
use DateTime;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;

#[ORM\Entity(repositoryClass: UserRepository::class)]
class User implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    // #[ORM\Id]
    #[ORM\Column(length: 90, unique:true)]
    private ?string $idUser = null;

    #[ORM\Column(length: 55)]
    private ?string $firstname = null;

    #[ORM\Column(length: 55)]
    private ?string $lastname = null;

    #[ORM\Column(length: 80, unique:true)]
    private ?string $email = null;

    #[ORM\Column(length: 90)]
    private ?string $encrypte = null;

    #[ORM\Column(length: 15, nullable: true)]
    private ?string $tel = null;

    #[ORM\Column(length: 15, nullable: true)]
    private ?int $sexe = null;

    #[ORM\Column]
    private ?\DateTime $datebirth = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $createAt = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $updateAt = null;

    #[ORM\OneToOne(mappedBy: 'User_idUser', cascade: ['persist', 'remove'])]
    private ?Artist $artist = null;

    #[ORM\Column(length: 15)]
    private ?bool $activated = false;

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getIdUser(): ?string
    {
        return $this->idUser;
    }

    public function setIdUser(string $idUser): static
    {
        $this->idUser = $idUser;

        return $this;
    }

    public function getFirstName(): ?string
    {
        return $this->firstname;
    }

    public function setFirstName(string $name): static
    {
        $this->firstname = $name;

        return $this;
    }

    public function getLastName(): ?string
    {
        return $this->lastname;
    }

    public function setLastName(string $name): static
    {
        $this->lastname = $name;

        return $this;
    }

    public function getUsername(): ?string
    {
        return $this->email;
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

    public function getPassword(): ?string
    {
        return $this->encrypte;
    }

    public function setPassword(string $encrypte): static
    {
        $this->encrypte = $encrypte;

        return $this;
    }

    public function getTel(): ?string
    {
        return $this->tel;
    }

    public function setTel(?string $tel): static
    {
        $this->tel = $tel;

        return $this;
    }

    public function getSexe(): ?int
    {
        return $this->sexe;
    }

    public function setSexe(?int $sexe): static
    {
        $this->sexe = $sexe;

        return $this;
    }

    public function getDateBirth(): ?string
    {
        return $this->datebirth->format('d-m-Y');;
    }

    public function setDateBirth(?DateTime $BirthDate): static 
    {
        $this->datebirth = $BirthDate;

        return $this;
    }
    
    public function getCreateAt(): ?string
    {
        return $this->createAt->format('Y-m-d');;
    }

    public function setCreateAt(\DateTimeImmutable $createAt): static
    {
        $this->createAt = $createAt;

        return $this;
    }

    public function getUpdateAt(): ?string
    {
        return $this->updateAt->format('Y-m-d');
    }

    public function setUpdateAt(\DateTimeInterface $updateAt): static
    {
        $this->updateAt = $updateAt;

        return $this;
    }

    public function getArtist(): ?Artist
    {
        return $this->artist;
    }

    public function setArtist(Artist $artist): static
    {
        // set the owning side of the relation if necessary
        if ($artist->getUserId() !== $this->getIdUser()) {
            $artist->setUserId($this);
        }

        $this->artist = $artist;

        return $this;
    }

    public function getStatut(): ?bool
    {
        return $this->activated;
    }

    public function setStatut(?bool $statut): static
    {
        $this->activated = $statut;

        return $this;
    }

    public function getRoles(): array{

        return ['PUBLIC_ACCESS'];
    }

    public function eraseCredentials(): void{

    }

    public function getUserIdentifier(): string{
        return $this->getEmail();
    }

    public function serializer()
    {
        return [
            "firstname" => $this->getFirstName(),
            "lastname" => $this->getLastName(),
            "email" => $this->getEmail(),
            "tel" => $this->getTel(),
            "sexe" => $this->getSexe(),
            "datebirth" => $this->getDateBirth(),
            "createAt" => $this->getCreateAt(),
            "updatedAt" => $this->getUpdateAt()
        ];
    }
}