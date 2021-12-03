

#### 一、 镜像扫描 ImagePolicyWebhook

题目概述：

```
context
A container image scanner is set up on the cluster,but It's not yet fully
integrated into the cluster's configuration When complete,the container image
scanner shall scall scan for and reject the use of vulnerable images.
task
You have to complete the entire task on the cluster master node,where all services and files have been prepared and placed
Glven an incomplete configuration in directory /etc/kubernetes/aa and a functional container image scanner with HTTPS sendpitont http://192.168.26.60:1323/image_policy

1.enable the necessary plugins to create an image policy
2.validate the control configuration and chage it to an implicit deny
3.Edit the configuration to point the provied HTTPS endpoint correctiy

Finally,test if the configurateion is working by trying to deploy the valnerable resource /csk/1/web1.yaml

```

解析：

切换集群，查看master,ssh master
1.引用插件

```shell
vim /etc/kubernetes/manifest/kube-apiserver.yaml
- --enable-admission-plugins=NodeRestriction,ImagePolicyWebhook
- --admission-control-config-file=/etc/kubernetes/aa/admission_configuration.json
```

2.编辑admission_configuration.json（题目会给），修改defaultAllow为false：

```
{
  "imagePolicy": {
     "kubeConfigFile": "/etc/kubernetes/aa/kubeconfig.yaml",
     "allowTTL": 50,
     "denyTTL": 50,
     "retryBackoff": 500,
     "defaultAllow": false  #改为false
  }
}
```

3.编辑/etc/kubernetes/aa/kubeconfig.yaml，添加 webhook server 地址：

```
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /etc/kubernetes/aa/webhook.pem
    server: http://192.168.26.60:1323/image_policy  #添加webhook server地址
  name: bouncer_webhook
contexts:
- context:
    cluster: bouncer_webhook
    user: api-server
  name: bouncer_validator
current-context: bouncer_validator
preferences: {}
users:
- name: api-server
  user:
    client-certificate: /etc/kubernetes/aa/apiserver-client.pem
    client-key:  /etc/kubernetes/aa/apiserver-clientkey.pem
```

4.挂载volume

```
volumes:
- hostPath:
    path: /etc/kubernetes/aa/
  name: xxx

volumeMounts:
- mountPath: /etc/kubernetes/aa/
  name: xxx
  #考试的时候会有个readOnly:true，删掉这行
```

5.重启kubelet

```
systemctl restart kubelet
kubectl apply -f /cks/1/web1.yaml
```

6.测试是否成功

```
kubectl run pod1 --image=nginx
```

https://kubernetes.io/zh/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook

#### 二、sysdig & faloc 检测pod

题目概述：

```
you may user you brower to open one additonal tab to access sysdig documentation ro Falco documentaion
Task:
user runtime detection tools to detect anomalous processes spawning and executing frequently in the sigle container belorging to Pod redis.
Tow tools are avaliable to use:
sysdig or falico
the tools are pre-installed on the cluster worker node only;the are not avaliable on the base system or the master node.
using the tool of you choice(including any non pre-install tool) analyse the container behaviour for at lest 30 seconds, using filers that detect newly spawing and executing processes.
store an incident file at /opt/2/report,containing the detected incidents one per line in the follwing format:
[timestamp],[uid],[processName]
```

解析：

从控制台 ssh 到 worker 节点，首先找到容器的 container id

```
root@vms62:~# docker ps | grep redis
5ae46a497d05   dc4395f73f8d                                        "docker-entrypoint.s…"   5 hours ago      Up 5 hours                k8s_redis_redis_default_a12b0575-919d-4d82-8d6d-f53671d181f7_2
6b715c0fea71   registry.aliyuncs.com/google_containers/pause:3.2   "/pause"                 5 hours ago      Up 5 hours                k8s_POD_redis_default_a12b0575-919d-4d82-8d6d-f53671d181f7_2

```

通过 sysdig 扫描容器30s并输出到指定文件：

```
# sysdig -l 查看帮助
sysdig -M 30  -p "*%evt.time,%user.uid,%proc.name" container.id=5ae46a497d05 > /opt/2/report
```

#### 三、clusterrole

题目概述：

```
context
A Role bound to a pod's serviceAccount grants overly permissive permission
Complete the following tasks to reduce the set of permissions.
task
Glven an existing Pod name web-pod running in the namespace monitoring Edit the
Roleebound to the Pod's serviceAccount sa-dev-1 to only allow performing list
operations,only on resources of type Endpoints
create a new Role named role-2 in the namespaces monitoring which only allows
performing update operations,only on resources of type persistentvoumeclaims.
create a new Rolebind name role role-2-bindding binding the newly created Roleto
the Pod's serviceAccount
```

解析：
1.修改sa-dev-1的role权限，只允许对endpoints做list操作
查看rolebindings sa-dev-1对应的role为role-1

```
root@vms60:/cks/9# kubectl get rolebindings -n monitoring
NAME       ROLE          AGE
sa-dev-1   Role/role-1   7d16h
```

编辑role-1权限：`kubectl edit role role-1 -n monitoring`

```
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  creationTimestamp: "2021-01-22T16:48:36Z"
  name: role-1
  namespace: monitoring
  resourceVersion: "9528"
  selfLink: /apis/rbac.authorization.k8s.io/v1/namespaces/monitoring/roles/role-1
  uid: 0dd5f94d-c27d-4052-a036-12c6c1006858
rules:
- apiGroups:
  - ""
  resources:
  - endpoints  #只允许对endpoints资源list
  verbs:
  - list
```

创建名为role-2的role，并且通过rolebinding绑定sa-dev-1，只允许对persistentvolumeclaims做update操作

```
kubectl create role role-2 --resource=persistentvolumeclaims --verb=update -n monitoring
kubectl create rolebinding role-2-binding --role=role-2 --serviceaccount=monitoring:sa-dev-1  -n monitoring
```

#### 四、apparmor

题目概述：

```
Context
AppArmor is enabled on the cluster's worker node. An AppArmor profile is prepared, but not enforced yet. You may use your browser to open one additional tab to access theAppArmor documentation. 
Task
On the cluster's worker node, enforce the prepared AppArmor profile located at
/etc/apparmor.d/nginx_apparmor . Edit the prepared manifest file located at
/cks/4/pod1.yaml to apply the AppArmor profile. Finally, apply the manifest file and create the pod specified in it
```

解析：

切换集群，从master,ssh到node节点
执行apparmor策略模块

```
apparmor_status |grep nginx-profile-3 # 没有grep到说明没有启动
cd /etc/apparmor.d
pparmor_parser -q nginx_apparmor # 加载启用这个配置文件
apparmor_status |grep nginx-profile-3
```

```
apiVersion: v1
kind: Pod
metadata:
  name: podx
  #添加annotations，podx名字和container的名字一样即可，nginx-profile-3为前面在worker上执行的apparmor策略模块
  annotations:
     container.apparmor.security.beta.kubernetes.io/podx: localhost/nginx-profile-3
spec:
  containers:
  - image: nginx:1.9
    imagePullPolicy: IfNotPresent
    name: podx
    resources: {}
  dnsPolicy: ClusterFirst
  restartPolicy: Always
status: {}
```

```
kubectl apply -f /cks/4/pod1.yaml
```

https://kubernetes.io/zh/docs/tutorials/clusters/apparmor/#%E4%B8%BE%E4%BE%8B

#### 五、PodSecurityPolicy

题目概述：

```
context
A PodsecurityPolicy shall prevent the creati on of privileged Pods in a specific namespace.
Task
Create a new PodSecurityPolicy named prevent-psp-policy , which prevents the creation of privileged Pods.
Create a new ClusterRole named restrict-access-role , which uses the newly created PodSecurityPolicy prevent psp-policy .
Create a new serviceAccount named psp-denial-sa in the existing namespace development .
Finally, create a new clusterRoleBinding named dany-access-bind , which binds the newlycreated ClusterRole restrict-access-role to the newly created serviceAccount
```

解析：

```
创建名为prevent-psp-policy的PodSecurityPolicy，阻止创建privileged Pod
创建名为restrict-access-role的ClusterRole允许使用新创建的名为prevent-psp-policy的PodSecurityPolicy。
在development命名空间中创建名为psp-denial-sa的serviceAccount。创建名为dany-access-bind的clusterRoleBinding，绑定刚刚创建的serviceAccount和ClusterRole。
```

需要从控制台ssh到master节点，确保/etc/kubernetes/manifest/kube-apiserver.yaml启用了PodSecurityPolicy。（考试中已经启用)

```
- --enable-admission-plugins=NodeRestriction,PodSecurityPolicy
```

创建名为prevent-psp-policy的PodSecurityPolicy，阻止创建Privileged Pod：

```
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: prevent-psp-policy
spec:
  privileged: false  #false表示禁止创建privileged的pod
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
```

创建ServiceAccount和CluserRole，并通过ClusterRoleBing绑定：

```
kubectl create clusterrole restrict-access-role --verb=use --resource=psp --resource-name=prevent-psp-policy
kubectl create sa psp-denial-sa -n development
kubectl create clusterrolebinding dany-access-bind --clusterrole=restrict-access-role --serviceaccount=development:psp-denial-sa
```

https://kubernetes.io/docs/concepts/policy/pod-security-policy/

#### 六、网络策略Networkpolicy

题目概述：

```
create a NetworkPolicy named pod-access torestrict access to Pod products-service running in namespace development .
only allow the following Pods to connect to Pod products-service :
Pods in the namespace testing
Pods with label environment: staging , in any namespace
Make sure to apply the NetworkPolicy. You can find a skelet on manifest file at /cks/6/p1.yaml
```

解析：

1. 主机查看pod的标签

   ```
   kubectl get pod -n development --show-labels
   ```

2. 查看对应ns的标签,没有需要设置一下

   ```
   kubectl label ns testing name=testing
   kubectl label pod products-service environment=staging
   ```

3. 创建networkpolicy

   ```
   apiVersion: networking.k8s.io/v1
   kind: NetworkPolicy
   metadata:
     name: pod-access
     namespace: development
   spec:
     podSelector:
       matchLabels:
          environment: staging
     policyTypes:
     - Ingress
     ingress:
     - from: #命名空间有name: testing标签的Pod
       - namespaceSelector:
           matchLabels:
             name: testing
     - from:  #所有命名空间有environment: staging标签的Pod
       - namespaceSelector:
           matchLabels:
         podSelector:
           matchLabels:
              environment: staging
   ```

   https://kubernetes.io/zh/docs/concepts/services-networking/network-policies/#networkpolicy-resource

#### 七、Dockerfile检测

题目概述：

```
Task
Analyze and edit the given Dockerfile (based on the ubuntu:16.04 image) /cks/7/Dockerfile, fixing two instructions present in the file being prominent security/best-practice issues.
Analyze and edit the given manifest file /cks/7/deployment.yaml fixing two fields present in the file being prominent security/best-practice issues.
```

解析：
检测 Dockerfile 的文件，有两处错误：

```
$ vim /cks/7/Dockerfile
#USER root
$ vim /cks/7/deployment.yaml
# securityContext:
#  {"Capabilities": {'add':{NET_BIND_SERVICE}, 'drop: []'}, 'privileged': TRUE}
```

```
#两处root注释即可
#USER root
```

```
修改为：apiVersion: apps/v1
注释：#{"Capabilities": {'add':{NET_BIND_SERVICE}, 'drop: []'}, 'privileged': TRUE}
```

#### 八、pod安全

题目概述

```
context
lt is best-practice to design containers to best teless and immutable.
Task
lnspect Pods running in namespace testing and delete any Pod that is either not stateless or not immutable.
use the following strict interpretation of stateless and immutable:
Pods being able to store data inside containers must be treated as not stateless.
You don’t have to worry whether data is actually stored inside containers or not already. Pods being configured to be privileged in any way must be treated as potentially not stateless and not immutable.
```

解析：

```
kubectl get pods NAME -n testing -o jsonpath={.spec.volumes} | jq
kubectl get pods NAME -o yaml -n testing | grep "privi.*: true"
kubectl delete pod xxxxx -n testing
```

#### 九、创建serviceaccount

题目概述：

```
context
A Pod fails to run because of an incorrectly specified ServiceAcccount.
Task
create a new ServiceAccount named frontend-sa in the existing namespace qa ,which must not have access to any secrets.
lnspect the Pod named frontend running in the namespace qa . Edit the Pod to use the newly created serviceAccount
```

解析：

在qa命名空间内创建ServiceAccount frontend-sa，不允许访问任何secrets。创建名为frontend-sa的Pod使用该ServiceAccount。

创建serviceaccount

```
apiVersion: v1
kind: ServiceAccount
automountServiceAccountToken: false #不自动挂载 secret
metadata:
  name: frontend-sa
  namespace: qa
```

创建pod，挂载sa

```
apiVersion: v1
kind: Pod
metadata:
  name: "frontend"
  namespace: "qa"
spec:
  serviceAccountName: "frontend-sa"
  containers:
  - image: nginx:1.9
    imagePullPolicy: IfNotPresent
    name: podx
    resources: {}
status: {}
```

删除没有使用的sa

```
root@vms60:/cks/9# kubectl delete sa -n qa default
serviceaccount "default" deleted
```

#### 10、trivy 检测镜像安全

题目概述：

```
Task
Use the Trivy open-source container scanner to detect images with severe vulnerabilities used by Pods in the namespace yavin .
Look for images with High or Critical severity vulnerabilities,and delete the Pods that use those images. Trivy is pre-installed on the cluster’s master node only; it is not available on the base system or the worker nodes. You’ll have to connect to the cluster’s master node to use Trivy
```

解析：
使用trivy扫描yavin命名空间内的Pod的镜像，并删除High或者Critical风险的Pod。trivy 安装在 master节点上，需要从控制台ssh登录过去
列出pod镜像:

```
root@vms60:/cks/9# kubectl get pod -n yavin
NAME        READY   STATUS    RESTARTS   AGE
baby-yoda   1/1     Running   1          7d11h
r2d2        1/1     Running   2          7d11h
rex         1/1     Running   1          7d11h
yoda        1/1     Running   1          7d11h

root@vms60:/cks/9# for i in baby-yoda r2d2 rex yoda ; do
> echo $i
> kubectl get pod $i -n yavin -o yaml | grep "image: "; done
baby-yoda
            f:image: {}
    image: amazonlinux:1
    image: amazonlinux:1
r2d2
            f:image: {}
    image: amazonlinux:1
    image: amazonlinux:1
rex
            f:image: {}
    image: alpine:3.12
    image: alpine:3.12
yoda
            f:image: {}
    image: alpine:3.12
    image: alpine:3.12

trivy image --skip-update amazonlinux:1 | egrep -i "High|Critical"
```

![img](https://img-blog.csdnimg.cn/img_convert/44b43847a0ebbc28f7866f86d005cc73.png)

[github.com/aquasecurity/trivy](https://github.com/aquasecurity/trivy)

#### 11、创建secret

题目概述：

```
Task
Retrieve the content of the existing secret named db1-test in the istio-system namespace.
store the username field in a file named /cks/11/old-username.txt , and the password field in a file named /cks/11/old-pass.txt.
You must create both files; they don exist yet.
Do not use/modify the created files in the following steps, create new temporaryfiles if needed.
Create a new secret named test-workflow in the istio-system namespace, with the following content:

username : thanos
password : hahahaha

Finally, create a new Pod that has access to the secret test-workflow via a volume:

pod name dev-pod
namespace istio-system
container name dev-container
image nginx:1.9
volume name dev-volume
mount path /etc/test-secret
```

解析：

将db1-test的username和password base64解码保存到指定文件：

```
kubectl get secrets -n istio-system db1-test -o jsonpath='{.data.username}'  | base64 -d >  /cks/11/old-username.txt
kubectl get secrets -n istio-system db1-test -o jsonpath='{.data.password}'  | base64 -d > /cks/11/old-pass.txt
```

创建名为test-workflow的secret使用
Username: thanos
Password: hahaha

```
kubectl create secret generic test-workflow --from-literal=username=thanos --from-literal=password=hahaha -n istio-system
```

创建pod使用该secret

```
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: dev-pod
  name: dev-pod #Pod名字
  namespace: istio-system #命名空间
spec:
  volumes:
  - name: dev-volume #创建volume
    secret:
      secretName: test-workflow
  containers:
  - image: nginx:1.9 #镜像版本
    name: dev-container #指定容器名字
    resources: {}
    volumeMounts:  #指定挂载路径
    - mountPath: /etc/test-secret
      name: dev-volume
  dnsPolicy: ClusterFirst
  restartPolicy: Always
status: {}
```

https://kubernetes.io/zh/docs/concepts/configuration/secret/

#### 12、kube-bench

题目概述：

```
context
ACIS Benchmark tool was run against the kubeadm-created cluster and found multiple issues that must be addressed immediately.

Task
Fix all issues via configuration and restart the affected components to ensure the new settings take effect. Fix all of the following violations that were found against the API server:

Ensure that the 1.2.7 --authorization-mode FAIL argument is not set to AlwaysAllow
Ensure that the 1.2.8 --authorization-mode FAIL argument includes Node
Ensure that the 1.2.9 --authorization-mode FAIL argument includes RBAC
Ensure that the 1.2.18 --insecure-bind-address FAIL argument is not set
Ensure that the 1.2.19 --insecure-port FAIL argument is set to 0

Fix all of the following violations that were found against the kubelet:

Ensure that the 4.2.1 anonymous-auth FAIL argument is set to false
Ensure that the 4.2.2 --authorization-mode FAIL argument is not set to AlwaysAllow
Use webhook authn/authz

Fix all of the following violations that were found against etcd:
Ensure that the 4.2.1 --client-cert-auth FAIL argument is set to true
```

解析：

需要从控制台ssh到master节点
1.api-server

```
#kube-bench master
1.2.7 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml
on the master node and set the --authorization-mode parameter to values other than AlwaysAllow.
One such example could be as below.
--authorization-mode=RBAC

1.2.8 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml
on the master node and set the --authorization-mode parameter to a value that includes Node.
--authorization-mode=Node,RBAC

1.2.9 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml
on the master node and set the --authorization-mode parameter to a value that includes RBAC,
for example:
--authorization-mode=Node,RBAC

1.2.18 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml
on the master node and remove the --insecure-bind-address parameter.

1.2.19 Edit the API server pod specification file /etc/kubernetes/manifests/kube-apiserver.yaml
on the master node and set the below parameter.
--insecure-port=0
```

vim /etc/kubernetes/manifests/kube-apiserver.yaml

```
#修改为
- --authorization-mode=Node,RBAC
- --insecure-port=0
#删除
- --insecure-bind-address=0.0.0.0
```

2.kubelet
vim /etc/systemd/system/kubelet.service.d/10-kubeadm.conf

```
#添加
Environment="KUBELET_SYSTEM_PODS_ARGS=--anonymous-auth=false"
Environment="KUBELET_SYSTEM_AUTH_ARGS=--authorization-mode=RBAC"

#追加
ExecStart后追加 $KUBELET_SYSTEM_PODS_ARGS $KUBELET_SYSTEM_AUTH_ARGS

#编辑完后重启kubelet
systemctl daemon-reload
systemctl restart kubelet.service
```

3.etcd
vim /etc/kubernetes/manifests/etcd.yaml

```
#kube-bench
2.2 Edit the etcd pod specification file /etc/kubernetes/manifests/etcd.yaml on the master
node and set the below parameter.
--client-cert-auth="true"
```

https://github.com/aquasecurity/kube-bench

#### 14、gVisor

题目概述：

```
context
This cluster uses containerd as CRl runtime. Containerd default runtime handler is runc .
Containerd has been prepared to support an additional runtime handler , runsc (gVisor).

Task
Create a RuntimeClass named untrusted using the prepared runtime handler namedrunsc .
Update all Pods in the namespace client to run on gvisor, unless they are already running on anon-default runtime handler. You can find a skeleton manifest file at /cks/13/rc.yaml
```

解析：

创建runtimeclass

```
apiVersion: node.k8s.io/v1beta1
kind: RuntimeClass
metadata:
  name: untrusted # 用来引用 RuntimeClass 的名字，RuntimeClass 是一个集群层面的资源
handler: runsc # 对应的 CRI 配置的名称
```

kubectl apply -f /cks/13/rc.yaml
Pod引用RuntimeClass,考试的时候pod是创建好的，通过kubectl edit修改

```
apiVersion: v1
kind: Pod
metadata:
  labels:
    run: pod
  name: nginx-gvisor
spec:
  containers:
  - image: nginx
    imagePullPolicy: IfNotPresent
    name: pod
  dnsPolicy: ClusterFirst
  restartPolicy: Always
  runtimeClassName: untrusted
```

https://github.com/google/gvisor

#### 14、审计

```
Task
Enable audit logs in the cluster.
To do so, enable the log backend, and ensurethat:

1.logs are stored at /var/log/kubernetes/audit-logs.txt
2.log files are retained for 5 days
3.at maximum, a number of 10 auditlog files are retained
A basic policy is provided at /etc/kubernetes/logpolicy/sample-policy.yaml. it only specifies what not to log.
The base policy is located on thecluster’s master node.
Edit and extend the basic policy to log:

1.namespaces changes at RequestResponse level
2.the request body of pods changes in the namespace front-apps
3.configMap and secret changes in all namespaces at the Metadata level
Also, add a catch-all ruie to log all otherrequests at the Metadata level.
Don’t forget to apply the modifiedpolicy.
```

解析：

登录master节点，编辑master节点的/etc/kubernetes/manifests/kube-apiserver.yaml文件，添加一下参数

```
#定义审计策略yaml文件位置，通过hostpath挂载
- --audit-policy-file=/etc/kubernetes/logpolicy/sample-policy.yaml
#定义审计日志位置，通过hostpath挂载
- --audit-log-path=/var/log/kubernetes/audit-logs.txt
#定义保留旧审计日志文件的最大天数为5天
- --audit-log-maxage=5
#定义要保留的审计日志文件的最大数量为10个
- --audit-log-maxbackup=10
```

配置hostpath

```
 volumes:
 - name: audit
    hostPath:
      path: /etc/kubernetes/logpolicy/sample-policy.yaml
      type: File
  - name: audit-log
    hostPath:
      path: /var/log/kubernetes/audit-logs.txt
      type: FileOrCreate
```

配置volumemount

```
volumeMounts:
  - mountPath: /etc/kubernetes/logpolicy/sample-policy.yaml
    name: audit
    readOnly: true
  - mountPath: /var/log/kubernetes/audit-logs.txt
    name: audit-log
    readOnly: false
```

配置审计策略：

```
apiVersion: audit.k8s.io/v1 # This is required.
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
  - "RequestReceived"
rules:
  #the request body of pods changes in the namespace front-apps
  - level: Request
    resources:
    - group: ""
      resources: ["pods"]
    namespaces: ["front-apps"]

  # namespaces changes at RequestResponse level
  - level: RequestResponse
    resources:
    - group: ""
      resources: ["namespace"]

  # Log configmap and secret changes in all other namespaces at the Metadata level.
  - level: Metadata
    resources:
    - group: ""
      resources: ["secrets", "configmaps"]

  # A catch-all rule to log all other requests at the Metadata level.
  - level: Metadata
    omitStages:
      - "RequestReceived"
```

配置完成后重启

```
systemctl restart kubelet
```

#### 15、默认网络策略

题目概述：

```
context
A default-deny NetworkPolicy avoids to accidentally expose a Pod in a namespace that doesn’t have any other NetworkPolicy defined.

Task
Create a new default-deny NetworkPolicy named denynetwork in the namespace development for all traffic of type Ingress .
The new NetworkPolicy must deny all lngress traffic in the namespace development .
Apply the newly created default-deny NetworkPolicy to all Pods running in namespace development .
You can find a skeleton manifest file
```

解析：

```
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: denynetwork
  namespace: development
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

#### 16、修改 API Server 参数

题目概述：

```
context
kubeadm was used to create the cluster used in this task.

Task
Reconfigure and restart the cluster’s Kubernetes APl server to ensure that only authenticated and authorized REST requests are allowed.
Make sure that the new configuration applies to any REST request, including local access.
Make sure that any configuration changes are permanent and still enforced after restarting the Kubernetes APl server.
```

解析：
确保只有认证并且授权过的REST请求才被允许。
编辑/etc/kubernetes/manifest/kube-apiserver.yaml，将下面内容

```
- --authorization-mode=AlwaysAllow
- --enable-admission-plugins=AlwaysAdmit
```

修改为：

```
- --authorization-mode=Node,RBAC
- --enable-admission-plugins=NodeRestriction
- --client-ca-file=/etc/kubernetes/pki/ca.crt
- --enable-bootstrap-token-auth=true
```

[docs/reference/command-line-tools-reference/kube-apiserver/](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)



