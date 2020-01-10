# Death

[@arobion][arobion]

```
Sommaire:
  I	  - Usage
  II	- Description
  III	- Fonctionement
          - Infection
            - Entry-Point Obscuring (EPO) technique
           - Insertion
          - Obfuscation
            - Anti debug
              - Anti breackpoint
              - Anti ptrace
              - Anti step by step
             - Section header obfuscation
              - Verification si un anti-virus
             - Close EPO
            - Polymorphisme
            - Metamorphisme
          - Backdoor
```
> ATTENTION : Ce projet est uniquement à **but pedagogique**.

## I - Usage

```shell
$> make
$> sh ./scripts/create_dir.sh #crée le dossier /tmp/test1 et /tmp/test2, copie les binaires ls, python, bash de /bin
$> ./death #infecte les deux dossiers
$> sh ./scripts/check.sh	#verifie si il y a des binaires infecté dans /tmp/test1 et /tmp/test2
$> sh ./scripts/infect.sh	#copie /tmp/test1/ls -> ./infected, recree le dossier /tmp/test1 et /tmp/test2, copie les binaires ls, python, bash de /bin et les infectes à partir de ./infected

#pour l'utilisation de la backdoor:
#modifier l'adresse IP dans ./src_s/anti_data.s
#être en root et lancer ./infected
$> sudo ./infected
#sur le poste qui a cette adresse IP lancer la commande
$> nc -l 5678 > keylogger.txt
#pour traduire les touches
$> python3 translate.py keylogger.txt
```

## II - Description

Ce projet est un virus metamorphique, qui est l'aboutissement de plusieurs projets:
- **WOODY-WOOPACKER**: Projet consistant à realiser un packer de elf64
- **FAMINE**: Projet consistant à crée un virus basique qui à pour but de simplement laisser une trace dans certains fichiers contenu dans un dossier spécifique
- **PESTILENCE**: Projet consistant à crée un virus obfusqué
- **WAR**: Projet consistant à crée un virus polymorphique

## III - Fonctionement

### Infection:
  - **Entry-Point Obscuring (EPO) technique**:
  
    Cette technique d'infection consiste à ouvrir plusieurs portes dans le binaire infecté, en remplacant dans celui-ci les appels de certaines fonctions par un jump sur notre virus et d'y revenir ensuite à la fin de l'execution de notre virus.
    Pour ce faire nous avons decidé d'infecter un binaire si il a plus de 50 ```call``` valides. C'est a dire une fonction commencant par le prolog ou alors si elle fait partie de la ```GOT```.
  - **Insertion**:
  
    Nous placons une partie de notre virus dans le padding de la section ```.text``` et le reste apres le ```.bss```.

### Obfuscation:

  #### Anti-debug:
  - **Anti breakpoint**:
      
      Lors du lancement de la routine d'infection, nous allons effectuer un ```hash``` de la partie de notre code qui permet le dechiffrement du ```payload```, puis nous allons utiliser ce ```hash``` en tant que clé de déchiffrement du ```payload```, qui, à la fin du déchiffrement aura une certaine valeure à laquelle nous ajoutons une autre valeure ( determinée lors de l'infection) qui correspond a l'adresse du debut du ```payload```.
      
      Ainsi, l'insertion d'un breakpoint corromp le ```hash``` ce qui entraine une mauvaise clé de déchiffremment ainsi qu'une mauvaise adresse du ```payload```.
  
  - **Anti ptrace**:
      
      Au lancement de la routine d'infection sur un binaire infecte, nous créons un enfant avec la commande ```fork```.
      
      Dans cet enfant nous essayons d'attacher le parent avec commande ```ptrace```, si l'attachement ne fonctionne pas nous arretons la routine d'infection.
      
      Si l'attachement fonctionne, nous allons dans l'enfant faire excuter la partie hash du père et récupérer cette valeur.
      
      Ensuite dans l'enfant nous allons executer la partie déchiffrement, et nous allons faire ```jump``` le parent à l'adresse obtenue.
  
  - **Anti step-by-step**:
      
      Vérification du Time-Stamp Counter grâce à l'insctrution ```rdtsc```.
      
      Vérification du ```RFLAGS``` ```TF``` grâce à l'insctruction ```pushfq```.
      
  - **Section header obfuscation**:
  
      Nous corrompons la section header pour ne plus avoir d'informations sur le binaire infecté.
      
  - **Verification de certains processus**:
  
      Nous recherchons si il y a un process avec le nom ```inhibitor```, si il est actif nous ne lancons pas notre virus.
      
  - **Close EPO**:
      
      Après le premier passage dans notre virus nous refermons les ```EPO``` pour ne plus repasser dans notre virus jusqu'à la fin de l'exécution du programme.
  
  #### Polymorphisme:
  Notre polymorphisme est basé sur un ```fingerprint``` unique, généré lors de l'infection du fichier.
  
  Ce fingerprint est obtenu grâce à un système de couplage ```index-fingerprint```, qui permet d'assurer un contrôle algorithmique de la génération du ```fingerprint```.
  
  Ce fingerprint est obtenu grâce à un système de couplage ```index-fingerprint```, qui permet d'assurer un contrôle algorithmique de la génération du ```fingerprint```.
  
  Grâce à ce fingerprint, nous obtenons des clés unique, nous permettant d'effectuer un chiffrement du ```payload``` different à chaque infection.
  
  Ce fingerprint est obtenu grâce à un système de couplage ```index-fingerprint```, qui permet d'assurer un contrôle algorithmique de la génération du ```fingerprint```.
  
  Chaque fonction du ```Payload``` est chiffrée grace à une clé unique issue d'un assemblage du fingerprint et du hash de cette fonction. 
  
  Lors de l'execution du ```Payload```, chaque fonction est ainsi déchiffrée avant son execution, puis rechiffrée des la fin de son execution, ce qui permet d'assurer une bonne protection contre l'analye dynamique.
  #### Metamorphisme:
  
   Nous avons dispatché dans la partie du virus non polymorphique des ```placeholder```.
   Nous les remplacons par différentes instructions, en fonction d'un motif généré à partir du ```fingerprint```.
    
| Exemples d'instructions | | | | | | 
| ------ | ------ | ------ | ------ | ------ | ------ |
| push rax  | nop | inc rax | dec rax | nop | push rax |
| nop | push rax | dec rax | inc rax | nop | pop rax |
| nop | pop rax | . | . | push rax | nop |
| pop rax | nop | . | . | pop rax | nop |

### Backdoor:
  La backdoor est un keylogger qui envoie les touches sur une adresse IP renseignée dans ```./srcs_s/anti_data.s``` sur le port ```5678```.




[arobion]: <https://github.com/arobion>
