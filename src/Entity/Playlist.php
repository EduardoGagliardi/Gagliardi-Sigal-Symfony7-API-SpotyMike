<?php

namespace App\Entity;

use App\Repository\PlaylistRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: PlaylistRepository::class)]
class Playlist
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    // #[ORM\Id]
    #[ORM\Column(length: 90)]
    private ?string $idPlaylist = null;

    #[ORM\Column(length: 50)]
    private ?string $title = null;

    #[ORM\Column]
    private ?bool $public = true;

    #[ORM\Column]
    private ?\DateTimeImmutable $createAt = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE)]
    private ?\DateTimeInterface $updateAt = null;

    #[ORM\ManyToOne(inversedBy: 'Playlist_idPlaylist')]
    private ?PlaylistHasSong $playlistHasSong = null;

    public function __construct()
    {}

    public function getId(): ?int
    {
        return $this->id;
    }

    public function getIdPlaylist(): ?string
    {
        return $this->idPlaylist;
    }

    public function setIdPlaylist(string $idPlaylist): static
    {
        $this->idPlaylist = $idPlaylist;

        return $this;
    }

    public function getTitle(): ?string
    {
        return $this->title;
    }

    public function setTitle(string $title): static
    {
        $this->title = $title;

        return $this;
    }

    public function isPublic(): ?bool
    {
        return $this->public;
    }

    public function setPublic(bool $public): static
    {
        $this->public = $public;

        return $this;
    }

    public function getCreateAt(): ?\DateTimeImmutable
    {
        return $this->createAt;
    }

    public function setCreateAt(\DateTimeImmutable $createAt): static
    {
        $this->createAt = $createAt;

        return $this;
    }

    public function getUpdateAt(): ?\DateTimeInterface
    {
        return $this->updateAt;
    }

    public function setUpdateAt(\DateTimeInterface $updateAt): static
    {
        $this->updateAt = $updateAt;

        return $this;
    }

    public function getPlaylistHasSong(): ?PlaylistHasSong
    {
        return $this->playlistHasSong;
    }

    public function setPlaylistHasSong(?PlaylistHasSong $playlistHasSong): static
    {
        $this->playlistHasSong = $playlistHasSong;

        return $this;
    }
}