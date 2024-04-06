<?php

namespace App\DataFixtures;

use App\Entity\Artist;
use DateTimeImmutable;
use App\Entity\User as EntityUser;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;

class User extends Fixture
{
    public function load(ObjectManager $manager): void
    {
        for ($i=0; $i < 6; $i++) { 
           
            $user = new EntityUser();
            $user->setName("User_".rand(0,999));
            $user->setEmail("User_".rand(0,999));
            $user->setIdUser("User_".rand(0,999));
            $user->setCreateAt(new DateTimeImmutable());
            $user->setUpdateAt(new DateTimeImmutable()); 
            $user->setPassword("$2y$".rand(0,999999999999999999));
            $manager->persist($user);
        }
        $manager->flush();
    }
}