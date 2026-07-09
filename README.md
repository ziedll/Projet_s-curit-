# But du projet :
Ce projet a pour but de renforcer un serveur appartenant à une entreprise fictive nommée "Techsud" qui a connue plusieurs attaques dues à des failles de sécurité, 
notamment des ports ouverts et des permissions élevées pour des comptes employés. C'est ainsi que nous allons procéder au renforcement de la sécurité informatique 
de l'entreprise en déployant un nouveau serveur Linux sous distribution Debian dans une machine virtuelle qu'on va configurer afin d'éviter que l'attaque ne se 
reproduise.
# Implémentation d'une GPO et d'une connexion ssh sécurisée
## GPO :
<img width="771" height="118" alt="image" src="https://github.com/user-attachments/assets/c38c74a1-611f-494e-97b7-779f6c46f778" />

création des groupes pour chaque secteur et réglages des permissions pour les répertoires afin de les isoler
### Script de création d'utilisateurs : 
Le script permet de faciliter la création d'utilisateurs pour les admin et leur ajout dans leur groupe respectif, il représente donc un outil incontournable pour facilier 
l'utilisation et accélerer les processus.
#### Script .sh pour la création de groupes

```bash
echo " === CREATION D'UN UTILISATEUR === "
read -p "Entrez le nom d'utilisateur : " username
read -p "Entrez le nom d'un groupe pour cet utilisateur : " groupname

if ! getent group "$groupname" > /dev/null 2>&1; then
echo "Nom du groupe incorrect"
exit 1
fi

if [ ! -d "/home/$groupname" ]; then
sudo mkdir -p "/home/$groupname'
sudo chgrp "$groupname" "/home/$groupname" 2>/dev/null
sudo chmod 2750 "/home/$groupname

sudo useradd -m -g "sgroupname" -d "/home/$groupname/Susername" -s /bin/bash "susername"

echo "Definissez le mdp pour $username : "
sudo passwd "susername"
echo "l'utilisateur $username a ete cree avec succes."

fi
```
### Script de recherches de groupes et d'affichage des membres de groupes 
Ce script permet à l'admin de savoir les membres de chaque groupe et aussi lui ajouter un système pour rechercher le secteur et ainsi afficher ses membres.
#### Scripts .sh de recherche de groupes :

```bash
cead -p "Entrez le nom du groupe a analyser : " groupname

if ! getent group "sgroupname" > /dev/null 2>&1; then
echo "Le groupe n'existe pas."
exit 1

fi

gid=$(getent group "$groupname" | cut -d: -f3)

echo "Utilisateurs du groupe : $groupname "
awk -F: -v gid="$gid" '$4 == gid{print$1}' /etc/passwd
```
#### Exemple de script .sh pour l'affichage de membres d'un secteur 

```
groupe="RH"
echo " === Membres du groupe $groupe === "

gid=$(getent group "$groupe" | cut -d: -f3)
echo "-Membres :"
awk -F: -v gid="$gid" '$4 == gid {print $1}' /etc/passwd
```

## Connexion SSH :
<img width="720" height="70" alt="image" src="https://github.com/user-attachments/assets/c4b83a9d-4686-4590-bc50-493939f019aa" />
<img width="808" height="81" alt="image" src="https://github.com/user-attachments/assets/1dbeedd6-eb27-46a9-b80a-5875ef6332bd" />


