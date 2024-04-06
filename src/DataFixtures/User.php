<?php

namespace App\DataFixtures;

use App\Entity\Artist;
use DateTimeImmutable;
use App\Entity\User as EntityUser;
use DateTime;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Persistence\ObjectManager;

class User extends Fixture
{

    public function load(ObjectManager $manager): void
    {
        $start_date = new DateTime('1980-01-01');
        $end_date = new DateTime();

        $start_timestamp = $start_date->getTimestamp();
        $end_timestamp = $end_date->getTimestamp();
        $diff = $end_timestamp - $start_timestamp;

        for ($i=0; $i < 6; $i++) { 
           // Define the start and end dates for the range

            $random_seconds = mt_rand(0, $diff);

            $user = new EntityUser();
            $user->setFirstName("User_".rand(0,999));
            $user->setLastName("User_".rand(0,999));
            $user->setEmail("User_".rand(0,999));
            $user->setIdUser("User_".rand(0,999));
            $user->setSexe(rand(0,1));
            $user->setTel("0".rand(100000000,999999999));
            $user->setDateBirth($random_datetime = DateTime::createFromFormat('U', ($start_timestamp + $random_seconds)));
            $user->setCreateAt(new DateTimeImmutable());
            $user->setUpdateAt(new DateTimeImmutable()); 
            $user->setPassword("$2y$".rand(0,999999999999999999));
            $manager->persist($user);
        }
        $manager->flush();
    }
}