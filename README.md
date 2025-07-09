# **DevOps Project: Book My Show App Deployment**

### **Phase 1: Initial Setup and Deployment**

**step 1: launch EC2 (ubuntu 22.04)**
 - Provision an EC2 instance on AWS with Ubuntu 22.04.
 - on security group  
    - SMTP → (Used for sending emails between mail servers) 

    - 3000-10000 → (Used by various applications, such as Node.js (3000), Grafana (3000), Jenkins (8080), and custom web applications.)

    - HTTP → Allows unencrypted web traffic. Used by web servers (e.g., Apache, Nginx) to serve websites over HTTP.

    - HTTPS → Allows secure web traffic using SSL/TLS.
 
    - SSH → Secure Shell (SSH) for remote server access.

    - 6443 → Kubernetes API server port. Used for communication between kubectl, worker nodes, and the Kubernetes control plane.

    - SMTPS → Secure Mail Transfer Protocol over SSL/TLS. Used for sending emails securely via SMTP with encryption

    - 30000-32767 → Kubernetes NodePort service range.

**step 2: Creation of EKS Cluster**

- Creation of IAM user (To create EKS Cluster, its not recommended to create using Root Account)
- Attach policies to the user 
  - AmazonEC2FullAccess
  - AmazonEKS_CNI_Policy
  - AmazonEKSClusterPolicy
  - AmazonEKSWorkerNodePolicy
  - AWSCloudFormationFullAccess
  - IAMFullAccess
  - Attach the below inline policy also for the same user
     ```json
     {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "eks:*",
            "Resource": "*"
        }
    ]
    }   
     ```
- Create Access Keys for the user created

***With this we have created the IAM User with appropriate permissions to create the EKS Cluster***

**step 3:install kubectl on server**

```bash
curl -o kubectl https://amazon-eks.s3.us-west-2.amazonaws.com/1.19.6/2021-01-05/bin/linux/amd64/kubectl
chmod +x ./kubectl
sudo mv ./kubectl /usr/local/bin
kubectl version --short --client
```
**step 4:install awscli on server**

```bash
sudo apt install unzip
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install
aws --version
```

**step 5:install eksctl on server**

```bash
curl --silent --location "https://github.com/weaveworks/eksctl/releases/latest/download/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
sudo mv /tmp/eksctl /usr/local/bin
eksctl version
```

**step 6:Create EKS cluster**

- Execute the below commands as separate set
    ```bash
    eksctl create cluster --name=kastro-eks \
                      --region=us-east-1 \
                      --zones=us-east-1a,us-east-1b \
                      --version=1.30 \
                      --without-nodegroup
    ```
- create iam role
    ```bash
    eksctl utils associate-iam-oidc-provider \
                          --region=us-east-1 \
                          --cluster=kastro-eks \
                          --approve
    ```
The above command is crucial when setting up an EKS cluster because it enables IAM roles for service accounts (IRSA)
Amazon EKS uses OpenID Connect (OIDC) to authenticate Kubernetes service accounts with IAM roles.
Associating the IAM OIDC provider allows Kubernetes workloads (Pods) running in the cluster to assume IAM roles securely.
Without this, Pods in EKS clusters would require node-level IAM roles, which grant permissions to all Pods on a node.
Without this, these services will not be able to access AWS resources securely

**step 6: Create nodegroup**

***Before executing the below command, in the 'ssh-public-key' keep the  '<PEM FILE NAME>' (dont give .pem. Just give the pem file name) which was used to create Jenkins Server***

```bash
eksctl create nodegroup --cluster=kastro-eks \
                       --region=us-east-1 \
                       --name=node2 \
                       --node-type=t3.medium \
                       --nodes=3 \
                       --nodes-min=2 \
                       --nodes-max=4 \
                       --node-volume-size=20 \
                       --ssh-access \
                       --ssh-public-key=Kastro \
                       --managed \
                       --asg-access \
                       --external-dns-access \
                       --full-ecr-access \
                       --appmesh-access \
                       --alb-ingress-access
```

For internal communication b/w control plane and worker nodes, open 'all traffic' in the security group of EKS Cluster

### **Phase 2: Install tools**

**step 1: install jenkns**

```bash
 vi jenkins.sh
 ```
INSIDE THIS 

```bash
#!/bin/bash
sudo apt install openjdk-17-jre-headless -y
sudo wget -O /usr/share/keyrings/jenkins-keyring.asc \ https://pkg.jenkins.io/debian-stable/jenkins.io-2023.key
echo deb [signed-by=/usr/share/keyrings/jenkins-keyring.asc] \ https://pkg.jenkins.io/debian-stable binary/ | sudo tee \ /etc/apt/sources.list.d/jenkins.list > /dev/null
sudo apt-get update
sudo apt-get install jenkins -y
```
----> esc ----> :wq 
```bash
sudo chmod +x jenkins.sh
```

```bash
./jenkins.sh
```

Open Port 8080 in Jenkins server
Access Jenkins and setup Jenkins

**step 2: install docker**

```bash
vi docker.sh
```

INSIDE THIS

```bash
#!/bin/bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \ $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 
```

 ----> esc ----> :wq

```bash
sudo chmod +x docker.sh
```

```bash
./docker.sh
```

Make sure to Login to DockerHub account in browser

Goto terminal --> Login to DockerHub ---> docker login -u <DockerHubUserName> ---> Click Enter ---> Enter the password of DockerHub 

**step 3: install trivy**

```bash
vi trivy.sh
```
INSIDE THIS 

```bash
#!/bin/bash
sudo apt-get install wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy
```

----> esc ----> :wq

```bash
sudo chmod +x trivy.sh 
```

```bash
./trivy.sh
```

**step 4:install Sonarqube using container**

Connect to the Jenkins Server

```bash
docker run -d --name sonar -p 9000:9000 sonarqube:lts-community
docker images
docker ps
```

Access SonarQube, after opening port 9000
Default username and Password: admin
Set new password



**step 5:Install necessary plugins**

Install below plugins

- Eclipse Temurin Installer (Install without restart)

- SonarQube Scanner (Install without restart)

- NodeJs Plugin (Install Without restart)

- OWASP Dependency-Check

- Pipeline: Stage view

- Docker

- Docker commons

- Docker API

- Docker-build-step

- Docker Pipeline

- Kubernetes

- Kubernetes CLI

- Kubernetes Client API

- Kubernetes Credentials

- Config File Provider

- Prometheus metrics

Restart when no jobs are running.

**step 6: Tools configuration**

Goto Manage Jenkins → Tools → 
- Install JDK(17) → enable install automatically → add installer → Import from adoptium.net → version jdk17.0.11+9
- Sonarqube scanner installations → add sonarqube → give name (sonar-scanner) 
- Nodejs installation → add Nodejs → give name (node23) 
- Dependency-Check installation → add dependency check → give name → (DP-Check) → enable install automatically → add installer → install from github.com
- Docker installation → add docker → give name (docker) → enable install automatically → add installer → Download from dockerhub

**step 7: sysytem configuration**

Goto jenkins dashboard → Manage jenkins → add sonarqube → give name (sonar-scanner) → paste the sonarqube ip with portnumber → add sonarqube credentals (sonar-token) → apply and save

**step 8: Creation of Credentials**

Goto jenkins dashboard → Manage jenkins → add sonarqube → give name (sonar-scanner) → paste the sonarqube ip with portnumber → add sonarqube credentals (sonar-token) → apply and save

**step 9: install npm**

```bash
apt install npm
```


### **Phase 3: Configure CI/CD Pipeline in jenkins (Without K8S Stage)**

- Goto Jenkins Dashboard → new item → give any name (swiggy app) → select pipeline → OK

```groovy
pipeline {
    agent any
    tools {
        jdk 'jdk17'
        nodejs 'node23'
    }
    environment {
        SCANNER_HOME = tool 'sonar-scanner'
    }
    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }
        stage('Checkout from Git') {
            steps {
                git branch: 'main', url: 'https://github.com/didin8080/Book-My-Show.git'
                sh 'ls -la'
            }
        }
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh '''
                    $SCANNER_HOME/bin/sonar-scanner -Dsonar.projectName=BMS \
                    -Dsonar.projectKey=BMS
                    '''
                }
            }
        }
        stage('Quality Gate') {
            steps {
                script {
                    sleep(time: 30, unit: 'SECONDS') // Allow time for webhook processing
                    timeout(time: 10, unit: 'MINUTES') {
                        def qg = waitForQualityGate()
                        if (qg.status != 'OK') {
                            error "Quality Gate failed: ${qg.status}"
                        }
                    }
                }
            }
        }
        stage('Install Dependencies') {
            steps {
                sh '''
                cd bookmyshow-app
                ls -la
                if [ -f package.json ]; then
                    rm -rf node_modules package-lock.json
                    npm install
                else
                    echo "Error: package.json not found in bookmyshow-app!"
                    exit 1
                fi
                '''
            }
        }
        stage('Trivy FS Scan') {
            steps {
                sh 'trivy fs . > trivyfs.txt'
            }
        }
        stage('Docker Build & Push') {
            steps {
                script {
                    withDockerRegistry(credentialsId: 'docker', toolName: 'docker') {
                        sh '''
                        echo "Building Docker image..."
                        docker build --no-cache -t didin8080/bms:latest -f bookmyshow-app/Dockerfile bookmyshow-app

                        echo "Pushing Docker image to registry..."
                        docker push didin8080/bms:latest
                        '''
                    }
                }
            }
        }
        stage('Deploy to Container') {
            steps {
                sh '''
                echo "Stopping and removing old container..."
                docker stop bms || true
                docker rm bms || true

                echo "Running new container on port 3000..."
                docker run -d --restart=always --name bms -p 3000:3000 didin8080/bms:latest

                echo "Checking running containers..."
                docker ps -a

                echo "Fetching logs..."
                sleep 5
                docker logs bms
                '''
            }
        }
    }
    post {
        always {
            emailext attachLog: true,
                subject: "'${currentBuild.result}'",
                body: "Project: ${env.JOB_NAME}<br/>" +
                      "Build Number: ${env.BUILD_NUMBER}<br/>" +
                      "URL: ${env.BUILD_URL}<br/>",
                to: 'kastrokiran@gmail.com',
                attachmentsPattern: 'trivyfs.txt,trivyimage.txt'
        }
    }
}
```
### **Replace the checout repo and generate the link using Pipeline Syntax**

Goto jenkins dashboard → select pipeline → scrolldown select pipeline Syntax → on sample step → select git:Git → paste the repo url → verify the branch → generate pipeline script → copy the link and paste it on checkout


Access the BMS App using Public IP of BMS-Server

Before executing the K8S Stage pipeline;

To know Jenkins is running on which user;
 ```bash
 ps aux | grep jenkins
 ```

 Look for the user in the output. For example:
jenkins   1234  0.0  0.1 123456 7890 ?        Ssl  12:34   0:00 /usr/bin/java -jar /usr/share/jenkins/jenkins.war
In this case, Jenkins is running as the jenkins user.


Switch to the jenkins user
```bash
sudo -su jenkins
pwd ---- /home/ubuntu
whoami ---- jenkins
```
Configure AWS credentials:
```aws configure``` ---> Configure with access and secret access keys
This will create the AWS credentials file at "/var/lib/jenkins/.aws/credentials"

Verify the credentials
aws sts get-caller-identity
If the credentials are valid, you should see output like this:
{
    "UserId": "EXAMPLEUSERID",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/example-user"
}

Comeout of the Jenkins user to Restart Jenkins

```bash
exit
sudo systemctl restart jenkins
```

Switch to Jenkins user
```bash
sudo -su jenkins
aws eks update-kubeconfig --name kastro-eks --region us-east-1
```


### **Phase 4: Configure CI/CD Pipeline in jenkins (With K8S Stage)**

```groovy
pipeline {
    agent any

    tools {
        jdk 'jdk17'
        nodejs 'node23'
    }

    environment {
        SCANNER_HOME = tool 'sonar-scanner'
        DOCKER_IMAGE = 'kastrov/bms:latest'
        EKS_CLUSTER_NAME = 'kastro-eks'
        AWS_REGION = 'ap-northeast-1'
    }

    stages {
        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }

        stage('Checkout from Git') {
            steps {
                git branch: 'main', url: 'https://github.com/didin8080/Book-My-Show.git'
                sh 'ls -la'  // Verify files after checkout
            }
        }

        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh ''' 
                    $SCANNER_HOME/bin/sonar-scanner \
                        -Dsonar.projectName=BMS \
                        -Dsonar.projectKey=BMS
                    '''
                }
            }
        }

        stage('Quality Gate') {
            steps {
                script {
                    waitForQualityGate abortPipeline: false, credentialsId: 'Sonar-token'
                }
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                cd bookmyshow-app
                ls -la  # Verify package.json exists
                if [ -f package.json ]; then
                    rm -rf node_modules package-lock.json  # Remove old dependencies
                    npm install  # Install fresh dependencies
                else
                    echo "Error: package.json not found in bookmyshow-app!"
                    exit 1
                fi
                '''
            }
        }

        stage('Trivy FS Scan') {
            steps {
                sh 'trivy fs . > trivyfs.txt'
            }
        }

        stage('Docker Build & Push') {
            steps {
                script {
                    withDockerRegistry(credentialsId: 'docker', toolName: 'docker') {
                        sh ''' 
                        echo "Building Docker image..."
                        docker build --no-cache -t $DOCKER_IMAGE -f bookmyshow-app/Dockerfile bookmyshow-app

                        echo "Pushing Docker image to Docker Hub..."
                        docker push $DOCKER_IMAGE
                        '''
                    }
                }
            }
        }

        stage('Deploy to EKS Cluster') {
            steps {
                script {
                    sh '''
                    echo "Verifying AWS credentials..."
                    aws sts get-caller-identity

                    echo "Configuring kubectl for EKS cluster..."
                    aws eks update-kubeconfig --name $EKS_CLUSTER_NAME --region $AWS_REGION

                    echo "Verifying kubeconfig..."
                    kubectl config view

                    echo "Deploying application to EKS..."
                    kubectl apply -f deployment.yml
                    kubectl apply -f service.yml

                    echo "Verifying deployment..."
                    kubectl get pods
                    kubectl get svc
                    '''
                }
            }
        }
    }

    post {
        always {
            emailext attachLog: true,
                subject: "'${currentBuild.result}'",
                body: "Project: ${env.JOB_NAME}<br/>" +
                      "Build Number: ${env.BUILD_NUMBER}<br/>" +
                      "URL: ${env.BUILD_URL}<br/>",
                to: 'kastrokiran@gmail.com',
                attachmentsPattern: 'trivyfs.txt'
        }
    }
}
```

### **Replace the checout repo and generate the link using Pipeline Syntax**

Goto jenkins dashboard → select pipeline → scrolldown select pipeline Syntax → on sample step → select git:Git → paste the repo url → verify the branch → generate pipeline script → copy the link and paste it on checkout


### **Phase 5: Monitoring the application**

**step 1: Launch EC2 (ubuntu 22.04)**

- Provision an EC2 instance on AWS with Ubuntu 22.04,t2.medium, name it as Monitering server.
- Connect to the instance using SSH.

**step 2: Install prometheus**

```bash
sudo apt update
sudo useradd --system --no-create-home --shell /bin/false prometheus
sudo wget https://github.com/prometheus/prometheus/releases/download/v2.47.1/prometheus-2.47.1.linux-amd64.tar.gz
tar -xvf prometheus-2.47.1.linux-amd64.tar.gz
sudo mkdir -p /data /etc/prometheus
cd prometheus-2.47.1.linux-amd64/
sudo mv prometheus promtool /usr/local/bin/
sudo mv consoles/ console_libraries/ /etc/prometheus/
sudo mv prometheus.yml /etc/prometheus/prometheus.yml
sudo chown -R prometheus:prometheus /etc/prometheus/ /data/
cd
rm -rf prometheus-2.47.1.linux-amd64.tar.gz
prometheus --version
```
COPY IT ONE BY ONE.

```bash
sudo vi /etc/systemd/system/prometheus.service
```
INSIDE THIS

```bash
[Unit]
Description=Prometheus
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=500
StartLimitBurst=5
[Service]
User=prometheus
Group=prometheus
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/prometheus \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.path=/data \
  --web.console.templates=/etc/prometheus/consoles \
  --web.console.libraries=/etc/prometheus/console_libraries \
  --web.listen-address=0.0.0.0:9090 \
  --web.enable-lifecycle
[Install]
WantedBy=multi-user.target
```
 ----> esc ----> :wq

```bash
sudo systemctl enable prometheus
sudo systemctl start prometheus
sudo systemctl status prometheus
```
you can see "active (running)" in green colour
Press control+c to come out of the file


`<public-ip:9090>`

Click on 'Status' dropdown ---> Click on 'Targets' ---> You can see 'Prometheus (1/1 up)' ----> It scrapes itself every 15 seconds by default.

**step 3:Install node exporter**


```bash
sudo useradd --system --no-create-home --shell /bin/false node_exporter
wget https://github.com/prometheus/node_exporter/releases/download/v1.6.1/node_exporter-1.6.1.linux-amd64.tar.gz
Extract Node Exporter files, move the binary, and clean up:
tar -xvf node_exporter-1.6.1.linux-amd64.tar.gz
sudo mv node_exporter-1.6.1.linux-amd64/node_exporter /usr/local/bin/
rm -rf node_exporter*
node_exporter --version
```
COPY IT ONE BY ONE.

```bash
sudo vi /etc/systemd/system/node_exporter.service
```

INSIDE THIS

```bash
[Unit]
Description=Node Exporter
Wants=network-online.target
After=network-online.target

StartLimitIntervalSec=500
StartLimitBurst=5

[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=on-failure
RestartSec=5s
ExecStart=/usr/local/bin/node_exporter --collector.logind

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable node_exporter
sudo systemctl start node_exporter
sudo systemctl status node_exporter
```

you can see "active (running)" in green colour
Press control+c to come out of the file

**step 4: Prometheus Configuration**

To configure Prometheus to scrape metrics from Node Exporter and Jenkins, you need to modify the prometheus.yml file.

```bash
cd /etc/prometheus/
ls -l
#You can see the "prometheus.yml" file
sudo vi prometheus.yml 
```
INSIDE THIS AT THE END OF THE FILE

```bash
- job_name: 'node_exporter'
    static_configs:
      - targets: ['<MonitoringVMip>:9100']

  - job_name: 'jenkins'
    metrics_path: '/prometheus'
    static_configs:
      - targets: ['<your-jenkins-ip>:<your-jenkins-port>']
```

 In the above, replace <your-jenkins-ip> and <your-jenkins-port> with the appropriate IPs ----> esc ----> :wq
Also replace the public ip of monitorting VM. Dont change 9100. Even though the Monitoring server is running on 9090, dont change 9100 in the above script.


Check the validity of the configuration file:
```bash
promtool check config /etc/prometheus/prometheus
```
You should see "SUCCESS" when you run the above command, it means every configuration made so far is good.

Reload the Prometheus configuration without restart
```bash
curl -X POST http://localhost:9090/-/reload
```

Access Prometheus in browser (if already opened, just reload the page):
`http://<your-prometheus-ip>:9090/targets`

For Node Exporter you will see (0/1) in red colour. To resolve this, open Port number 9100 for Monitoring VM 

You should now see "Jenkins (1/1 up)" "node exporter (1/1 up)" and "prometheus (1/1 up)" in the prometheus browser.
Click on "showmore" next to "jenkins." You will see a link. Open the link in new tab, to see the metrics that are getting scraped



**step 5: Install prometheus**

You are currently in /etc/Prometheus path.

```bash
sudo apt-get update
sudo apt-get install -y apt-transport-https software-properties-common
cd
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
#You should see OK when executed the above command.
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list
sudo apt-get update
sudo apt-get -y install grafana
sudo systemctl enable grafana-server
sudo systemctl start grafana-server
sudo systemctl status grafana-server
```
You should see "Active (running)" in green colour
Press control+c to come

Access Grafana Web Interface: The default port for Grafana is 3000
`http://<monitoring-server-ip>:30`

Default id and password is "admin"
You can Set new password or you can click on "skip now".
Click on "skip now" (If you want you can create the password)


Adding Data Source in Grafana
The first thing that we have to do in Grafana is to add the data source
Add the data source

Adding Dashboards in Grafana; (URL: https://grafana.com/grafana/dashboards/1860-node-exporter-full/) 

Lets add another dashboard for Jenkins; (URL: https://grafana.com/grafana/dashboards/9964-jenkins-performance-and-health-overview/)

Click on Dashboards in the left pane, you can see both the dashboards you have just added.

