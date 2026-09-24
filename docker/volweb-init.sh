#!/bin/sh
# VolWeb superuser init — exécuté par l'entrypoint.sh de l'image VolWeb
# après les migrations, avant de démarrer Daphne.
#
# Crée ou met à jour le compte admin pour qu'il corresponde toujours à
# VOLWEB_USER / VOLWEB_PASSWORD définis dans .env — aucune étape manuelle.

set -e

if [ -z "$DJANGO_SUPERUSER_PASSWORD" ]; then
  echo "[volweb-init] DJANGO_SUPERUSER_PASSWORD absent — superuser ignoré"
else
  python manage.py shell -c "
import os
from django.contrib.auth import get_user_model
User = get_user_model()

username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
email    = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@forensiclab.local')

user, created = User.objects.get_or_create(username=username)
user.set_password(password)
user.is_staff     = True
user.is_superuser = True
if not user.email:
    user.email = email
user.save()

action = 'cree' if created else 'mis a jour'
print(f'[volweb-init] Superuser \"{username}\" {action}')
"
fi

exec daphne -b 0.0.0.0 -p 8000 backend.asgi:application
