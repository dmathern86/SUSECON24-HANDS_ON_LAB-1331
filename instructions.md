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

