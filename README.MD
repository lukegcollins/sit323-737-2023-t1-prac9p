# sit323-737-2023-t1-prac9p

This repository provides an implementation of a math and login service connected to a MongoDB database, all within a Kubernetes environment.

## Table of Contents
- [sit323-737-2023-t1-prac9p](#sit323-737-2023-t1-prac9p)
  - [Table of Contents](#table-of-contents)
  - [Requirements](#requirements)
  - [Installation](#installation)
    - [MongoDB Service](#mongodb-service)
    - [Login and Math Services](#login-and-math-services)
  - [Usage](#usage)
    - [Login Service](#login-service)
    - [Math Service](#math-service)
  - [Troubleshooting](#troubleshooting)
  - [Contributing](#contributing)

## Requirements
- Kubernetes (K8s) cluster environment 
- kubectl CLI
- Docker 

## Installation
Clone the repository with the following command:
``

### MongoDB Service
First, we need to create the Kubernetes entities for the storage class and persistent volume. Run the following commands in your terminal:
```
kubectl apply -f .\storageClass.yaml
kubectl apply -f .\persistentVolume.yaml
kubectl apply -f .\persistentVolumeClaim.yaml
```

### Login and Math Services
Now, let's create the Kubernetes entities for the Mongo, Math, and Login Services:
```
kubectl apply -f .\mongoService.yaml
kubectl apply -f .\loginService.yaml
kubectl apply -f .\mathService.yaml
kubectl apply -f .\mongoServiceDeployment.yaml
kubectl apply -f .\loginServiceDeployment.yaml
kubectl apply -f .\mathServiceDeployment.yaml
kubectl get services

```
The `kubectl get services` command will provide you with the IP addresses for the Login and Math services.

## Usage
### Login Service
The Login Service provides user registration, password updates, and authentication.

- POST /register  
  Payload: `{ "username": "<username>", "password": "<password>" }`
- POST /changepass  
  Payload: `{ "username": "<username>", "password": "<current_password>", "newpass": "<new_password>" }`
- POST /deleteuser  
  Payload: `{ "username": "<username>" }`
- POST /login  
  Payload: `{ "username": "<username>", "password": "<password>" }`

### Math Service
The Math Service provides basic math functions.

- POST /add  
  Payload: `{ "num1": <number>, "num2": <number> }`
- POST /multiply    
  Payload: `{ "num1": <number>, "num2": <number> }`
- POST /subtract  
  Payload: `{ "num1": <number>, "num2": <number> }`
- POST /divide  
  Payload: `{ "num1": <number>, "num2": <number> }`

**Note:** You need to include the JWT token received from the login service in the request header for authorization in the math service.

## Troubleshooting
If you encounter any issues, check the logs of the pods: `kubectl logs <pod-name>`


If you still face issues, feel free to open an issue on this GitHub repository.

## Contributing

Contributions are welcome! Please read the [contribution guidelines](CONTRIBUTING.md) first.

