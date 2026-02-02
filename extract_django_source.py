import os
import fnmatch

# Définir les extensions à inclure et exclure
include_extensions = ['*.py', '*.html', '*.css', '*.js']
exclude_extensions = ['*.pyc']

# Dossiers à exclure (utiliser os.path.normpath pour la portabilité)
exclude_dirs = [
    'migrations',
    'myenv',
    'venv',
    'env',
    '__pycache__'
]

output_file = 'django_project_source.txt'

# Ouvrir le fichier de sortie en mode append (ajout)
with open(output_file, 'a', encoding='utf-8') as out:
    # Parcourir récursivement le répertoire courant
    for root, dirs, files in os.walk('.'):
        # Filtrer les dossiers à exclure (modifier dirs in-place pour skipper les sous-dirs)
        dirs[:] = [d for d in dirs if d not in exclude_dirs]
        
        for file in files:
            # Vérifier les extensions incluses et exclues
            if any(fnmatch.fnmatch(file, ext) for ext in include_extensions) and \
               not any(fnmatch.fnmatch(file, ext) for ext in exclude_extensions):
                
                full_path = os.path.join(root, file)
                print(f"Processing file: {full_path}")
                
                # Ajouter le séparateur avec le chemin
                out.write(f"========== {full_path} ==========\n")
                
                # Lire et écrire le contenu du fichier
                with open(full_path, 'r', encoding='utf-8') as f:
                    out.write(f.read())
                
                # Ajouter une ligne vide
                out.write("\n\n")
