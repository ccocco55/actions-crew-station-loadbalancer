
# ⚖️ Load Balancing Architecture

## 🧩 개요
본 서비스는 **AWS EC2 인스턴스 두 대(Spring1, Spring2)** 를 대상으로 **Nginx Load Balancer**를 구성하여 트래픽을 분산 처리하는 구조로 설계되었습니다.  
클라이언트(Web, Mobile) 요청은 `Route53`을 통해 도메인으로 접근하며, Nginx가 각 Spring 서버로 요청을 분배합니다.

---

## ☁️ 인프라 구성도

![슬라이드3](https://github.com/user-attachments/assets/21b71112-ea81-4039-90f5-0a85f7ff6d22)

---

## ⚙️ 구성 요소

| 구성 요소 | 역할 |
|------------|------|
| **Route53** | 도메인 라우팅 및 트래픽 전달 |
| **Nginx (EC2)** | 리버스 프록시 및 로드 밸런서 역할 수행 |
| **Spring Boot (EC2 x2)** | 애플리케이션 서버 (Docker 기반 실행) |
| **PostgreSQL** | 주요 데이터 저장소 |
| **Redis** | 세션 및 캐시 관리 |
| **Amazon S3** | 정적 파일(이미지 등) 저장 |
| **GitHub Actions** | CI/CD 자동 배포 파이프라인 구성 |
| **Git-Secret** | AWS 인증 정보 및 환경 변수 암호화 관리 |

---

## ⚖️ 로드밸런싱

###  🔽 Nginx 설치 
```
# 설치
sudo apt install nginx

# 파일 만들기
sudo vim /etc/nginx/sites-available/[앱 이름]
```

### 🔧 Nginx 설정
```
/etc/nginx/sites-available/[앱 이름]-loadbalancer
```

``` nginx
/etc/nginx/sites-available/[앱 이름]-loadbalancer
```

``` nginx
upstream [앱 이름] {
	# 요청을 서버 순서대로 균등하게 분배하는 방식
        least_conn;
	# 차례대로 할꺼면 아무것도 안쓰기

	# 클라이언트 IP를 해싱하여 항상 같은 서버로 요청 전달
	      # ip_hash;

        server ipaddress1:80;  # 첫 번째 EC2
        server ipaddress2:80;  # 두 번째 EC2
}

server {
        listen 80;

        location / {
                proxy_pass http://[앱 이름];
                proxy_set_header Host $host;
                proxy_set_header X-Real-IP $remote_addr;
    }
}
```

--- 
✔️ 적용/상태 확인

```
# 기존 링크 삭제
sudo rm /etc/nginx/sites-enabled/default

# 만든 파일 링크 걸어주기
sudo ln -s /etc/nginx/sites-available/[이름] /etc/nginx/sites-enabled/

# 확인
ls -l /etc/nginx/sites-enabled/

# 설정한 파일에 문제 체크
sudo nginx -t
```

## 🔄 트래픽 흐름

1. 사용자가 **Web(Chrome)** 또는 **Mobile(React Native)** 앱을 통해 요청 전송  
2. `Route53`이 요청을 **Nginx 로드밸런서**로 전달  
3. Nginx가 `least_conn` 방식으로 두 EC2(Spring Boot 서버) 중 하나로 요청 분배  
4. 각 서버는 Docker 컨테이너 내에서 Spring Boot 애플리케이션 실행  
5. 애플리케이션은 **PostgreSQL**, **Redis**, **S3** 등 외부 리소스와 연동  
6. 응답은 Nginx를 거쳐 클라이언트로 반환  

---

## 🧱 CI/CD 파이프라인

1. 개발자가 로컬에서 코드 수정 후 GitHub에 **push**  
2. **GitHub Actions**가 트리거되어 `deploy.yml` 실행  
3. `Dockerfile`을 기반으로 이미지 빌드 및 배포  
4. `Git-Secret`을 사용해 민감한 환경 변수 및 AWS IAM Key를 안전하게 관리  

> 배포는 두 개의 EC2(Spring1, Spring2)에 동일하게 반영되어  
> Nginx 로드밸런싱 환경에서 무중단 서비스가 가능하도록 구성되어 있습니다.

---

## 🧩 확장성 및 장애 대응

- 새로운 EC2(Spring) 인스턴스 추가 시, Nginx `upstream` 블록에 서버 정보를 추가하는 것만으로 확장이 가능합니다.
- 특정 서버 장애 발생 시, Nginx가 자동으로 요청을 다른 서버로 우회하여 **서비스 중단 최소화**가 가능합니다.
- Stateless 구조로 설계되어, **세션은 Redis**에 저장되어 서버 간 공유가 가능합니다.

---

## 🛠️ 사용 기술 스택

| 영역 | 기술 |
|------|------|
| Infra | AWS EC2, Route53, S3, IAM |
| Backend | Spring Boot, Spring Security, JWT |
| Database | PostgreSQL |
| Cache | Redis |
| Proxy / LB | Nginx |
| CI/CD | GitHub Actions, Docker |
| Client | React Native, Web (Chrome) |

---

## 📈 기대 효과

- ✅ **부하 분산**을 통한 안정적인 트래픽 처리를 할 수 있습니다. 
- ✅ **서버 장애 시 자동 우회**로 가용성 향상이 가능 합니다.
- ✅ **CI/CD 자동화**로 배포 속도 및 일관성을 확보 할 수 있습니다.
- ✅ **Stateless 아키텍처**로 확장성을 강화 할 수 있습니다.
