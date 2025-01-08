while true
do
  pytest --cov=. -s -v -W ignore::DeprecationWarning
  sleep 86400
done

