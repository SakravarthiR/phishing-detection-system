#!/bin/bash

# =====================================================
# PRODUCTION DEPLOYMENT SCRIPT
# Automates deployment to Namecheap/VPS
# =====================================================

set -e  # Exit on error

echo "🚀 Starting deployment..."

# Configuration
PROJECT_NAME="phishing-detector"
DEPLOY_USER="www-data"
DEPLOY_PATH="/var/www/${PROJECT_NAME}"
VENV_PATH="${DEPLOY_PATH}/.venv"
BACKEND_PATH="${DEPLOY_PATH}/backend"
FRONTEND_PATH="${DEPLOY_PATH}/frontend"
LOG_PATH="/var/log/${PROJECT_NAME}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Step 1: Update system
echo -e "${YELLOW}📦 Updating system packages...${NC}"
sudo apt-get update
sudo apt-get upgrade -y

# Step 2: Install dependencies
echo -e "${YELLOW}📦 Installing system dependencies...${NC}"
sudo apt-get install -y \
    python3.11 \
    python3.11-venv \
    python3-pip \
    nginx \
    supervisor \
    git \
    curl \
    certbot \
    python3-certbot-nginx

# Step 3: Create application user (if doesn't exist)
if ! id "$DEPLOY_USER" &>/dev/null; then
    echo -e "${YELLOW}👤 Creating application user...${NC}"
    sudo useradd -r -s /bin/bash -d $DEPLOY_PATH $DEPLOY_USER
fi

# Step 4: Create directory structure
echo -e "${YELLOW}📁 Creating directory structure...${NC}"
sudo mkdir -p $DEPLOY_PATH
sudo mkdir -p $LOG_PATH
sudo mkdir -p /var/www/letsencrypt

# Step 5: Clone repository (or copy files)
echo -e "${YELLOW}📥 Deploying application files...${NC}"
if [ -d "$DEPLOY_PATH/.git" ]; then
    cd $DEPLOY_PATH
    sudo git pull origin main
else
    # Copy from current directory
    sudo cp -r . $DEPLOY_PATH/
fi

# Step 6: Set permissions
echo -e "${YELLOW}🔒 Setting permissions...${NC}"
sudo chown -R $DEPLOY_USER:$DEPLOY_USER $DEPLOY_PATH
sudo chown -R $DEPLOY_USER:$DEPLOY_USER $LOG_PATH
sudo chmod -R 755 $DEPLOY_PATH
sudo chmod -R 755 $LOG_PATH

# Step 7: Create Python virtual environment
echo -e "${YELLOW}🐍 Creating Python virtual environment...${NC}"
cd $DEPLOY_PATH
sudo -u $DEPLOY_USER python3.11 -m venv $VENV_PATH

# Step 8: Install Python dependencies
echo -e "${YELLOW}📦 Installing Python packages...${NC}"
sudo -u $DEPLOY_USER $VENV_PATH/bin/pip install --upgrade pip
sudo -u $DEPLOY_USER $VENV_PATH/bin/pip install -r $BACKEND_PATH/requirements.txt
sudo -u $DEPLOY_USER $VENV_PATH/bin/pip install gunicorn

# Step 9: Create .env file (if doesn't exist)
if [ ! -f "$DEPLOY_PATH/.env" ]; then
    echo -e "${YELLOW}⚙️  Creating environment file...${NC}"
    sudo cp $DEPLOY_PATH/.env.example $DEPLOY_PATH/.env
    echo -e "${RED}⚠️  IMPORTANT: Edit $DEPLOY_PATH/.env with your configuration!${NC}"
fi

# Step 10: Configure Nginx
echo -e "${YELLOW}🌐 Configuring Nginx...${NC}"
sudo cp $DEPLOY_PATH/deployment/nginx.conf /etc/nginx/sites-available/$PROJECT_NAME
sudo ln -sf /etc/nginx/sites-available/$PROJECT_NAME /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx

# Step 11: Configure systemd service
echo -e "${YELLOW}⚙️  Configuring systemd service...${NC}"
sudo cp $DEPLOY_PATH/deployment/$PROJECT_NAME.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable $PROJECT_NAME
sudo systemctl restart $PROJECT_NAME

# Step 12: Configure firewall
echo -e "${YELLOW}🔥 Configuring firewall...${NC}"
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
sudo ufw --force enable

# Step 13: Setup SSL with Let's Encrypt
echo -e "${YELLOW}🔒 Setting up SSL certificate...${NC}"
read -p "Enter your domain name (e.g., yourdomain.com): " DOMAIN
read -p "Enter your email for SSL notifications: " EMAIL

sudo certbot --nginx \
    -d $DOMAIN \
    -d www.$DOMAIN \
    --non-interactive \
    --agree-tos \
    --email $EMAIL \
    --redirect

# Step 14: Setup cron job for SSL renewal
echo -e "${YELLOW}⏰ Setting up SSL auto-renewal...${NC}"
(crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet --post-hook 'systemctl reload nginx'") | sudo crontab -

# Step 15: Final checks
echo -e "${YELLOW}✅ Running health checks...${NC}"
sleep 5
if curl -f http://localhost:5000/health > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Backend API is running!${NC}"
else
    echo -e "${RED}❌ Backend API health check failed!${NC}"
fi

if systemctl is-active --quiet $PROJECT_NAME; then
    echo -e "${GREEN}✅ Service is active!${NC}"
else
    echo -e "${RED}❌ Service is not running!${NC}"
fi

if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}✅ Nginx is running!${NC}"
else
    echo -e "${RED}❌ Nginx is not running!${NC}"
fi

# Step 16: Display status
echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}   DEPLOYMENT COMPLETE!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "📊 Service Status:"
sudo systemctl status $PROJECT_NAME --no-pager | head -n 10
echo ""
echo "🌐 Your application is now running at:"
echo "   https://$DOMAIN"
echo ""
echo "📝 Logs:"
echo "   Application: sudo journalctl -u $PROJECT_NAME -f"
echo "   Nginx Access: tail -f /var/log/nginx/phishing-detector-access.log"
echo "   Nginx Error: tail -f /var/log/nginx/phishing-detector-error.log"
echo ""
echo "🔧 Useful commands:"
echo "   Restart service: sudo systemctl restart $PROJECT_NAME"
echo "   View logs: sudo journalctl -u $PROJECT_NAME -f"
echo "   Check status: sudo systemctl status $PROJECT_NAME"
echo ""
echo -e "${YELLOW}⚠️  Next steps:${NC}"
echo "   1. Edit $DEPLOY_PATH/.env with your production settings"
echo "   2. Update frontend API URLs to point to your domain"
echo "   3. Test the application thoroughly"
echo "   4. Setup monitoring (optional)"
echo ""
