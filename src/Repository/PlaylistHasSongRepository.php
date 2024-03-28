<?php

namespace App\Repository;

use App\Entity\PlaylistHasSong;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @extends ServiceEntityRepository<PlaylistHasSong>
 *
 * @method PlaylistHasSong|null find($id, $lockMode = null, $lockVersion = null)
 * @method PlaylistHasSong|null findOneBy(array $criteria, array $orderBy = null)
 * @method PlaylistHasSong[]    findAll()
 * @method PlaylistHasSong[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class PlaylistHasSongRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, PlaylistHasSong::class);
    }

    //    /**
    //     * @return PlaylistHasSong[] Returns an array of PlaylistHasSong objects
    //     */
    //    public function findByExampleField($value): array
    //    {
    //        return $this->createQueryBuilder('p')
    //            ->andWhere('p.exampleField = :val')
    //            ->setParameter('val', $value)
    //            ->orderBy('p.id', 'ASC')
    //            ->setMaxResults(10)
    //            ->getQuery()
    //            ->getResult()
    //        ;
    //    }

    //    public function findOneBySomeField($value): ?PlaylistHasSong
    //    {
    //        return $this->createQueryBuilder('p')
    //            ->andWhere('p.exampleField = :val')
    //            ->setParameter('val', $value)
    //            ->getQuery()
    //            ->getOneOrNullResult()
    //        ;
    //    }
}
