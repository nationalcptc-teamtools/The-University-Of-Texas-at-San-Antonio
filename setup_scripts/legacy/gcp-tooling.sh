# This is for installing gcp tools
mkdir ~/gcp-tooling
cd ~/gcp-tooling

# Install gcloud cli
curl -O https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-linux-x86_64.tar.gz
tar -xf google-cloud-cli-linux-x86_64.tar.gz
./google-cloud-sdk/install.sh -q

# Install the rest of the gcp tools
git clone https://github.com/NetSPI/gcpwn.git
git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation.git
git clone https://github.com/TeneBrae93/gcp-tooling.git
