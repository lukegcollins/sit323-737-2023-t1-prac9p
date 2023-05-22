# sit323-737-2023-t1-prac9p

### Starting MongoDB Service
Use the following commands to create the Kubernetes entities for the storage class and persistent volume.

```
kubectl apply -f .\storageClass.yaml
kubectl apply -f .\persistentVolume.yaml
kubectl apply -f .\persistentVolumeClaim.yaml
kubectl get services
```

### Starting Login and Math Service
Use the following commands to create the Kubernetes entities for the Mongo, Math and Login Service:

```
kubectl apply -f .\mongoService.yaml
kubectl apply -f .\loginService.yaml
kubectl apply -f .\mathService.yaml
kubectl apply -f .\mongoServiceDeployment.yaml
kubectl apply -f .\loginServiceDeployment.yaml
kubectl apply -f .\mathServiceDeployment.yaml
kubectl get services
```
