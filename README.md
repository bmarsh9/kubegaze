<p align="center">
  <img height="120px" src="https://github.com/bmarsh9/kubegaze/blob/18df6b7e0d565c8f41fc4600c229811c56b2f2b7/ui/app/static/img/kubegaze_full.png" alt="Logo"/>
</p>

#### Get started in 1 minute!

Stream and filter events          |  
:-------------------------:|
![](ui/app/static/img/kubegaze_2.PNG)  |

#### Getting the cluster started
sudo snap install microk8s --classic
sudo microk8s.status --wait-ready
sudo microk8s.config
sudo microk8s.kubectl cluster-info
sudo microk8s.kubectl get pods --all-namespaces

#### Starting deployment
- `invoke generate_keys webhook webhook`
- copy cert to config/validate.yml file
- `microk8s.kubectl --namespace=webhook create secret tls webhook-certs --cert=keys/server.crt --key=keys/server.key`
- `microk8s.kubectl apply -f config/deployment.yaml`
- `microk8s.kubectl apply -f config/validate.yaml`

#### Debug
microk8s.kubectl get validatingwebhookconfigurations
microk8s.kubectl delete validatingwebhookconfigurations.admissionregistration.k8s.io validating-webhook
microk8s.kubectl delete secret webhook-certs -n webhook
microk8s.kubectl delete deployments webhook -n webhoo
microk8s.kubectl exec --stdin --tty webhook-8647f75dd6-gprxb -n webhook -- bash
invoke generate_keys webhook webhook
openssl x509 -text -noout -in keys/server.crt
microk8s.kubectl delete pod nginx --grace-period=0 --force
microk8s.kubectl logs webhook-7b49f7f5b-xkkgm -n webhook -f

##### Check admission compat
microk8s.kubectl api-versions | grep admissionregistration


