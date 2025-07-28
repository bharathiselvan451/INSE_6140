#!/bin/sh
cd /Applications/XAMPP/htdocs/scan
composer install
sudo /Applications/XAMPP/xamppfiles/xampp start
if [ ! -f /Applications/XAMPP/htdocs/scan/wordpress/wp-config.php ]; then
    sudo wp config create --dbname=scan --dbuser=root --dbpass= --path=/Applications/XAMPP/htdocs/scan/wordpress --allow-root
    sudo sed -i.bu '103i\
    define( "'WP_AUTO_UPDATE_CORE'", false );' wordpress/wp-config.php
fi
sudo chown -R daemon:daemon /Applications/XAMPP/htdocs/scan/wordpress
wp plugin activate woocommerce --path=/Applications/XAMPP/htdocs/scan/wordpress
wp plugin activate woocommerce-payments --path=/Applications/XAMPP/htdocs/scan/wordpress
wp plugin activate elementor --path=/Applications/XAMPP/htdocs/scan/wordpress
wp plugin activate ele-custom-skin --path=/Applications/XAMPP/htdocs/scan/wordpress
dependency-check --enableExperimental --format CSV  --out /Users/divyaprabharajendran/Documents/INSE_6140/scan_results   --scan /Applications/XAMPP/xamppfiles/htdocs/scan
wpscan --url http://localhost/scan/wordpress/   --output /Users/divyaprabharajendran/Documents/INSE_6140/scan_results/wpscan.json --format json --api-token KJPgLXv4IiRiQZsDVHBqMlh1EWFZHqWj1s0YjwrK7MY
wordfence vuln-scan --output-format csv --output-columns cve --output-path /Users/divyaprabharajendran/Documents/INSE_6140/scan_results/wordfence.csv /Applications/XAMPP/xamppfiles/htdocs/scan/wordpress
phpcs -p --extensions=php -d memory_limit=1500M --report=csv --report-file=/Users/divyaprabharajendran/Documents/INSE_6140/scan_results/PHPCS.csv --standard=WordPress .
sudo sonar-scanner \
  -Dsonar.projectKey=local \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=sqp_e0fcda791ccb5ba84723a04c3a5ab3de5969c5b8
python /Users/divyaprabharajendran/Documents/INSE_6140/result_scan.py
