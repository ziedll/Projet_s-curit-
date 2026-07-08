#!/bin/bash
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/var/backups/web"
tar -czf "$BACKUP_DIR/backup_$DATE.tar.gz" /var/www/html /etc/nginx/sites-enabled
find "$BACKUP_DIR" -type f -mtime +30 -delete
echo "Backup terminé : backup_$DATE.tar.gz"
