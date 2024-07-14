## TP Spring Security 

## Opération à faire : 

- Le projet est une application bancaire très basique.
- L'objectif est de sécuriser l'application avec une authentification par jwt et une gestion des rôles appropriée.
- Lancer le projet et vérifier qu'il fonctionne bien. Effectuez les correctifs nécéssaires.
- Mettre en place les éléments de sécurité suivant : 
    - Être authentifié et avoir le rôle USER pour accéder à :
        - Account, Loans, Balance et Cards. Mais uniquement ses propres informations personnelles.
        - Ex: Un User ne peut accéder qu'à ses propres comptes notamment grâce à son id (l'information doit être retournée lors de la phase de login)
    - Être authentifié et avoir le rôle ADMIN ou USER pour accéder à :
        - Balance.
    - Tout le monde peut accéder à  :
        - notices, contact, login et register
    - Seul le rôle ADMIN permet de lister l'ensemble des emprunts, des cartes, des comptes, transactions et des users.
- Pour effectuer vos vérifications, vous aurez besoin de postman.
- A la fin de du TP, envoyez moi sur Teams en MP le dépôt git du TP.