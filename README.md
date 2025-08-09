# Spring Boot JWT Authentication example with Spring Security & Spring Data JPA

 MySQL:
```xml
<dependency>
  <groupId>com.mysql</groupId>
  <artifactId>mysql-connector-j</artifactId>
  <scope>runtime</scope>
</dependency>
- For MySQL
```
#DataSource Configuration(Mysql)
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.datasource.url=jdbc:mysql://localhost:3306/miniproject_springsecurity
spring.datasource.username=root
spring.datasource.password=521996

#JPA-Hibernate Properties
#spring.jpa.database-platform=org.hibernate.dialect.OracleDialect
spring.jpa.database-platform=org.hibernate.dialect.MySQL8Dialect
spring.jpa.show-sql=true
spring.jpa.hibernate.ddl-auto=update
spring.jpa.properties.hibernate.enable_lazy_load_no_trans=true

# App Properties
ashu.app.jwtSecret= =jshdauifd9whq8ie2qhfug09382erh8qwuegyfuiqsgdwqyui==22yevdhbduuqwhjb--
ashu.app.jwtExpirationInMs=86400000
```



