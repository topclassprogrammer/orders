cd /app/orders/
python manage.py migrate
python manage.py load_fixtures
python manage.py collectstatic

psql -h db -p 5432 -d orders -U postgres -c "CREATE ROLE root WITH SUPERUSER LOGIN;"
psql -h db -p 5432 -d orders -U postgres -c "CREATE DATABASE root;"

psql -h db -p 5432 -d orders -U postgres -c "
SELECT setval(pg_get_serial_sequence('backend_role', 'id'), coalesce(max(id), 0) + 1, false) FROM backend_role;
SELECT setval(pg_get_serial_sequence('backend_user', 'id'), coalesce(max(id), 0) + 1, false) FROM backend_user;
"

gunicorn orders.wsgi -b 0.0.0.0:8000 -w 3
