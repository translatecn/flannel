# /etc/cni/net.d/10-flannel.conflist

```
{
  "name": "cbr0",
  "cniVersion": "0.3.1",
  "plugins": [
    {
      "type": "flannel",
      "delegate": {
        "hairpinMode": true,
        "isDefaultGateway": true
      }
    },
    {
      "type": "portmap",
      "capabilities": {
        "portMappings": true
      }
    }
  ]
}
```

- vxlan : 将二层报文用三层协议进行封装，实现二层网络在三层内(ip)内进行扩展。


- [nftables用法介绍] https://cloud.tencent.com/developer/article/2385128 




1、创建 flannel 相关的 iptables
2、调用 bridge + host-local
3、