<?php

namespace App\Entity;

use App\Repository\PlaylistHasSongRepository;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\Collections\Collection;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity(repositoryClass: PlaylistHasSongRepository::class)]
class PlaylistHasSong
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column]
    private ?int $id = null;

    #[ORM\OneToMany(targetEntity: Playlist::class, mappedBy: 'playlistHasSong')]
    private Collection $Playlist_idPlaylist;

    #[ORM\OneToMany(targetEntity: Song::class, mappedBy: 'playlistHasSong')]
    private Collection $Song_idSong;

    #[ORM\Column(nullable: true)]
    private ?bool $download = null;

    #[ORM\Column(type: Types::SMALLINT, nullable: true)]
    private ?int $position = null;

    #[ORM\Column]
    private ?\DateTimeImmutable $createAt = null;

    public function __construct()
    {
        $this->Playlist_idPlaylist = new ArrayCollection();
        $this->Song_idSong = new ArrayCollection();
    }

    public function getId(): ?int
    {
        return $this->id;
    }

    /**
     * @return Collection<int, Playlist>
     */
    public function getPlaylistIdPlaylist(): Collection
    {
        return $this->Playlist_idPlaylist;
    }

    public function addPlaylistIdPlaylist(Playlist $playlistIdPlaylist): static
    {
        if (!$this->Playlist_idPlaylist->contains($playlistIdPlaylist)) {
            $this->Playlist_idPlaylist->add($playlistIdPlaylist);
            $playlistIdPlaylist->setPlaylistHasSong($this);
        }

        return $this;
    }

    public function removePlaylistIdPlaylist(Playlist $playlistIdPlaylist): static
    {
        if ($this->Playlist_idPlaylist->removeElement($playlistIdPlaylist)) {
            // set the owning side to null (unless already changed)
            if ($playlistIdPlaylist->getPlaylistHasSong() === $this) {
                $playlistIdPlaylist->setPlaylistHasSong(null);
            }
        }

        return $this;
    }

    /**
     * @return Collection<int, Song>
     */
    public function getSongIdSong(): Collection
    {
        return $this->Song_idSong;
    }

    public function addSongIdSong(Song $songIdSong): static
    {
        if (!$this->Song_idSong->contains($songIdSong)) {
            $this->Song_idSong->add($songIdSong);
            $songIdSong->setPlaylistHasSong($this);
        }

        return $this;
    }

    public function removeSongIdSong(Song $songIdSong): static
    {
        if ($this->Song_idSong->removeElement($songIdSong)) {
            // set the owning side to null (unless already changed)
            if ($songIdSong->getPlaylistHasSong() === $this) {
                $songIdSong->setPlaylistHasSong(null);
            }
        }

        return $this;
    }

    public function isDownload(): ?bool
    {
        return $this->download;
    }

    public function setDownload(?bool $download): static
    {
        $this->download = $download;

        return $this;
    }

    public function getPosition(): ?int
    {
        return $this->position;
    }

    public function setPosition(?int $position): static
    {
        $this->position = $position;

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
}
