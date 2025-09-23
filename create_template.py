#!/usr/bin/env python3
"""
Script d'automatisation de création des templates
Exécutez: python create_templates.py
"""

import os
from pathlib import Path

# Structure des templates à créer
TEMPLATES_STRUCTURE = {
    'data_admin': [
        'admin_dashboard.html',
        'admin_database.html', 
        'admin_table_view.html',
        'admin_users.html',
        'admin_mandats.html',
        'admin_notifications.html',
        'admin_settings.html',
        'admin_reports.html'
    ],
    
    'user_agent': [
        'agent_dashboard.html',
        'deposer_mandat.html',
        'mes_mandats.html',
        'suivi_mandat.html',
        'mandat_detail.html',
        'agent_profile.html',
        'agent_statistiques.html'
    ],
    
    'user_fournisseur': [
        'fournisseur_dashboard.html',
        'mes_mandats_fournisseur.html',
        'suivi_mandat_fournisseur.html',
        'mandat_detail_fournisseur.html',
        'fournisseur_profile.html',
        'fournisseur_statistiques.html',
        'historique_paiements.html'
    ]
}

# Contenu de base pour chaque template
BASE_TEMPLATE_CONTENT = """{{% extends "base.html" %}}

{{% block title %}}{page_title}{{% endblock %}}

{{% block content %}}
<div class="container">
    <div class="row">
        <div class="col-12">
            <h1>{page_title}</h1>
            <p>Template {template_name} - En cours de développement</p>
            
            <div class="alert alert-info">
                <i class="fas fa-info-circle"></i> 
                Cette page est en cours de construction. Contenu à compléter.
            </div>
        </div>
    </div>
</div>
{{% endblock %}}
"""

# Contenu spécifique pour certains templates
SPECIAL_TEMPLATES = {
    'data_admin/admin_dashboard.html': """{{% extends "base.html" %}}

{{% block title %}}Tableau de Bord Administrateur{{% endblock %}}

{{% block content %}}
<div class="container-fluid">
    <h1 class="mb-4">📊 Tableau de Bord Administrateur</h1>
    
    <div class="row">
        <div class="col-md-3">
            <div class="card text-white bg-primary">
                <div class="card-body">
                    <h5 class="card-title">👥 Utilisateurs</h5>
                    <h2>{{ stats.utilisateurs_total }}</h2>
                    <small>Total des utilisateurs</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-success">
                <div class="card-body">
                    <h5 class="card-title">📄 Mandats</h5>
                    <h2>{{ stats.mandats_total }}</h2>
                    <small>Total des mandats</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-warning">
                <div class="card-body">
                    <h5 class="card-title">🔔 Notifications</h5>
                    <h2>{{ stats.notifications_total }}</h2>
                    <small>Notifications système</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-info">
                <div class="card-body">
                    <h5 class="card-title">⚙️ Système</h5>
                    <h2>Actif</h2>
                    <small>Statut de l'application</small>
                </div>
            </div>
        </div>
    </div>
</div>
{{% endblock %}}
""",
    
    'user_agent/agent_dashboard.html': """{{% extends "base.html" %}}

{{% block title %}}Tableau de Bord Agent{{% endblock %}}

{{% block content %}}
<div class="container-fluid">
    <h1 class="mb-4">👨‍💼 Tableau de Bord Agent</h1>
    
    <div class="row">
        <div class="col-md-4">
            <div class="card text-white bg-primary">
                <div class="card-body">
                    <h5 class="card-title">📤 Mandats Déposés</h5>
                    <h2>{{ stats.mandats_deposes }}</h2>
                    <small>Total de vos mandats</small>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card text-white bg-success">
                <div class="card-body">
                    <h5 class="card-title">📋 En Cours</h5>
                    <h2>{{ stats.mandats_en_cours }}</h2>
                    <small>Mandats en traitement</small>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card text-white bg-info">
                <div class="card-body">
                    <h5 class="card-title">✅ Validés</h5>
                    <h2>{{ stats.mandats_valides }}</h2>
                    <small>Mandats approuvés</small>
                </div>
            </div>
        </div>
    </div>
    
    <div class="mt-4">
        <a href="{{ url_for('mandats_bp.deposer_mandat') }}" class="btn btn-success">
            <i class="fas fa-plus"></i> Déposer un Nouveau Mandat
        </a>
        <a href="{{ url_for('mandats_bp.mes_mandats') }}" class="btn btn-outline-primary">
            <i class="fas fa-list"></i> Voir Mes Mandats
        </a>
    </div>
</div>
{{% endblock %}}
""",
    
    'user_fournisseur/fournisseur_dashboard.html': """{{% extends "base.html" %}}

{{% block title %}}Tableau de Bord Fournisseur{{% endblock %}}

{{% block content %}}
<div class="container-fluid">
    <h1 class="mb-4">🏢 Tableau de Bord Fournisseur</h1>
    
    <div class="row">
        <div class="col-md-3">
            <div class="card text-white bg-primary">
                <div class="card-body">
                    <h5 class="card-title">📄 Mandats Reçus</h5>
                    <h2>{{ stats.mandats_total }}</h2>
                    <small>Total des mandats</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-warning">
                <div class="card-body">
                    <h5 class="card-title">⏳ En Attente</h5>
                    <h2>{{ stats.mandats_attente }}</h2>
                    <small>En cours de traitement</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-success">
                <div class="card-body">
                    <h5 class="card-title">💰 Payés</h5>
                    <h2>{{ stats.mandats_payes }}</h2>
                    <small>Mandats réglés</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-white bg-info">
                <div class="card-body">
                    <h5 class="card-title">📈 Montant Total</h5>
                    <h2>{{ stats.montant_total }} FCFA</h2>
                    <small>Chiffre d'affaires</small>
                </div>
            </div>
        </div>
    </div>
    
    <div class="mt-4">
        <a href="{{ url_for('mandats_bp.mes_mandats') }}" class="btn btn-primary">
            <i class="fas fa-file-invoice"></i> Mes Mandats
        </a>
        <a href="#" class="btn btn-outline-success">
            <i class="fas fa-chart-line"></i> Statistiques
        </a>
    </div>
</div>
{{% endblock %}}
"""
}

def create_template_file(folder, filename):
    """Crée un fichier template avec le contenu approprié"""
    filepath = Path('templates') / folder / filename
    
    # Créer le dossier s'il n'existe pas
    filepath.parent.mkdir(parents=True, exist_ok=True)
    
    # Vérifier si le fichier existe déjà
    if filepath.exists():
        print(f"⚠️  {filepath} existe déjà - ignoré")
        return False
    
    # Déterminer le contenu du template
    key = f"{folder}/{filename}"
    if key in SPECIAL_TEMPLATES:
        content = SPECIAL_TEMPLATES[key]
    else:
        # Générer un titre à partir du nom du fichier
        page_title = filename.replace('.html', '').replace('_', ' ').title()
        content = BASE_TEMPLATE_CONTENT.format(
            page_title=page_title,
            template_name=filename
        )
    
    # Créer le fichier
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return True

def main():
    print("🚀 Création automatique des templates...")
    print("=" * 50)
    
    total_created = 0
    total_existing = 0
    
    for folder, templates in TEMPLATES_STRUCTURE.items():
        print(f"\n📁 Création des templates pour: {folder}/")
        print("-" * 30)
        
        for template in templates:
            if create_template_file(folder, template):
                print(f"✅ {template} créé")
                total_created += 1
            else:
                total_existing += 1
    
    print("\n" + "=" * 50)
    print(f"📊 RÉSUMÉ:")
    print(f"✅ Templates créés: {total_created}")
    print(f"⚠️  Templates existants: {total_existing}")
    print(f"📁 Dossiers traités: {len(TEMPLATES_STRUCTURE)}")
    print("\n🎯 Structure finale créée!")
    
    # Afficher l'arborescence finale
    print("\n🌳 ARBORESCENCE FINALE:")
    display_tree()

def display_tree():
    """Affiche l'arborescence des templates"""
    templates_dir = Path('templates')
    
    for item in templates_dir.rglob('*'):
        if item.is_dir():
            print(f"📁 {item.relative_to(templates_dir)}/")
            for file in item.glob('*.html'):
                print(f"   📄 {file.name}")
        elif item.is_file() and item.suffix == '.html':
            print(f"📄 {item.relative_to(templates_dir)}")

if __name__ == '__main__':
    main()