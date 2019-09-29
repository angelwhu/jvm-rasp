package com.angelwhu;

import com.alibaba.fastjson.JSON;
import com.alibaba.jvm.sandbox.api.Information;
import com.alibaba.jvm.sandbox.api.LoadCompleted;
import com.alibaba.jvm.sandbox.api.Module;
import com.alibaba.jvm.sandbox.api.ProcessControlException;
import com.alibaba.jvm.sandbox.api.http.Http;
import com.alibaba.jvm.sandbox.api.listener.ext.Advice;
import com.alibaba.jvm.sandbox.api.listener.ext.AdviceListener;
import com.alibaba.jvm.sandbox.api.listener.ext.EventWatchBuilder;
import com.alibaba.jvm.sandbox.api.resource.ModuleEventWatcher;
import com.angelwhu.alarm.ResponseProcess;
import com.angelwhu.util.StackTrace;
import com.angelwhu.model.*;
import com.baidu.openrasp.TokenGenerator;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.dom4j.Document;
import org.dom4j.DocumentException;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.kohsuke.MetaInfServices;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.*;

/**
 * 基于RASP技术的RCE漏洞攻击检测
 *
 * @author angelwhu
 */
@MetaInfServices(Module.class)
@Information(id = "detect-SQL-injection", isActiveOnLoad = true, version = "0.0.1", author = "angelwhu")
public class DetectSQLInjectionModule implements Module, LoadCompleted {

    private final Logger stLogger = LoggerFactory.getLogger("DETECT-SQL-INJECTION-LOGGER");

    private final List<String> blacklists = new ArrayList<String>(
            Arrays.asList("java.lang.Runtime",
            "java.lang.Class",
            "java.lang.ClassLoader",
            "java.lang.System",
            "java.lang.ProcessBuilder",
            "java.lang.Object",
            "java.lang.Shutdown",
            "java.io.File"));

    private final List<String> expressionPattern = new ArrayList<String>(
            Arrays.asList("ognl.Ognl@getValue",
                    "ognl.Ognl@setValue",
                    "SpelExpression@getValue",
                    "SpelExpression@setValue"));

    private final List<String> deserializationPattern = new ArrayList<String>(
            Arrays.asList("java.io.ObjectInputStream@readObject"));

    private ThreadLocal<MultilayerMessageWrapper> wrapMessageDataRef = new ThreadLocal<MultilayerMessageWrapper>() {
        @Override
        protected MultilayerMessageWrapper initialValue() {
            return null;
        }
    };

    private ThreadLocal<Object> responseCache = new ThreadLocal<Object>() {
        @Override
        protected HttpServletResponse initialValue() {
            return null;
        }
    };

    @Resource
    private ModuleEventWatcher moduleEventWatcher;

    @Override
    public void loadCompleted() {
//        buildBehaviorWatcher();
//        buildExpressionWatcher();
//        buildApplicationWatcher();
//        buildHttpServletWatcher();
    }

    @Http("/sql_injection_detect")
    public void sqli_detect(final HttpServletRequest req, final HttpServletResponse resp) //req,resp is Jetty's input and output. @angelwhu 2018/04/24
    {
        buildBehaviorWatcher();
        buildExpressionWatcher();
        buildApplicationWatcher();
        buildHttpServletWatcher();
    }

    public void buildBehaviorWatcher()
    {
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("java.lang.ProcessBuilder")
                /**/.includeBootstrap()
                .onBehavior("start")
                .onWatch(new AdviceListener() {
                    @Override
                    public void before(Advice advice) throws Throwable {
                        /**
                         * Must throw ProcessControlException to control process. @angelwhu 2018/04/23
                         * see com.alibaba.jvm.sandbox.core.enhance.weaver.EventListenerHandlers line 114 to catch the Exception.
                         */
                        /**
                         * static Process start(String cmdarray[],
                         java.util.Map<String,String> environment,
                         String dir,
                         ProcessBuilder.Redirect[] redirects,
                         boolean redirectErrorStream)
                         拦截这个函数即可~
                         */
                        //System.err.println("agent test~ before ProcessBuilder start");
                        Object processBuildObject =  advice.getTarget();
                        List<String> cmdArray = null;
                        try {
                            cmdArray= (List<String>) FieldUtils.readDeclaredField(processBuildObject,"command",true);
                        } catch (IllegalAccessException e) {
                            e.printStackTrace();
                        }
                        stLogger.info("try to exec: {}",StringUtils.join(cmdArray, " "));
                        stLogger.info(StackTrace.getStackTrace());

                        if(wrapMessageDataRef.get() == null)
                        {
                            wrapMessageDataRef.set(new MultilayerMessageWrapper());
                        }
                        wrapMessageDataRef.get().getdBehaviorLayerMessage().setBehavior(DBehaviorLayerMessage.Behavior.executeCMD);
                        wrapMessageDataRef.get().getdBehaviorLayerMessage().setMessage(StringUtils.join(cmdArray, " "));

                        JudgeResult judgeResult = new JudgeResult();
                        judgeResult.setAttack(true);
                        judgeResult.setAttackType(JudgeResult.AttackType.rceAttack);
                        judgeResult.setRiskLevel(JudgeResult.RiskLevel.HIGH);

                        String stackTraceString = StackTrace.getStackTrace();
                        if(checkExpressionAttack(stackTraceString))
                        {
                            processExpressionAttack(judgeResult);
                        }
                        else if(checkDeserializationAttack(stackTraceString))
                        {
                            processDeserializationAttack(judgeResult);
                        }
                        else
                        {
                            judgeResult.setResultMessage("未知利用方式,请查看各层次消息");
                        }
                        /**
                         * ToDo: Set UID to multilayer messages and Judge Result. @angelwhu 2018/05/01
                         */

                        wrapMessageDataRef.get().storeMultilayerMessages(); // Store multilayer messages. @angelwhu 2018/04/25
                        judgeResult.processJudgeResult(wrapMessageDataRef.get(),stackTraceString); //Process the attack information. @angelwhu 2018/04/25

                        if(responseCache.get() !=null)
                        {
                            ResponseProcess responseProcess = new ResponseProcess(responseCache.get());
                            responseProcess.sendAlarmToViews("You are a good man~");
                            // Throw runtimeException, to end the business. @angelwhu 2018/04/26
                            RuntimeException runtimeException = new RuntimeException("Block by rasp");
                            ProcessControlException.throwThrowsImmediately(runtimeException);
                        }
                        else
                        {
                            String cmd = "echo 'You are a good man~'";
                            Runtime run = Runtime.getRuntime();//返回与当前 Java 应用程序相关的运行时对象
                            Process p = null;
                            try {
                                p = run.exec(cmd);
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                            // 然后立即返回，因为监听的是BEFORE事件，所以此时立即返回，方法体将不会被执行
                            ProcessControlException.throwReturnImmediately(p);
                        }
                    }

                    /**
                     * Check OGNL or SpEL through pattern. @angelwhu 2018/04/24
                     * OGNL: ognl.Ognl@getValue, ognl.Ognl@setValue
                     * SpEL: SpelExpression@getValue, SpelExpression@setValue
                     */
                    public boolean checkExpressionAttack(String stackTraceString)
                    {
                        for(String pattern : expressionPattern)
                        {
                            if(stackTraceString.contains(pattern))
                            {
                                return true;
                            }
                        }
                        return false;
                    }

                    public void processExpressionAttack(JudgeResult judgeResult)
                    {
                        String attackMessage = "";
                        CExpressionLayerMessage.LanguageType languageType = wrapMessageDataRef.get().getcExpressionLayerMessage().getLanguageType();
                        if(languageType == null)
                        {
                            judgeResult.setResultMessage("疑似表达式语言攻击，请查看具体各层次拦截信息");
                            return;
                        }
                        switch (languageType){
                            case OGNL: attackMessage = attackMessage + "OGNL语言执行:";
                                break;
                            case SpEL: attackMessage = attackMessage + "SpEL语言执行:";
                                break;
                            default: break;
                        }
                        attackMessage = attackMessage + wrapMessageDataRef.get().getcExpressionLayerMessage().getExpression();
                        judgeResult.setResultMessage(attackMessage);
                    }

                    /**
                     * Check deserialization attack through stacktrace. @angelwhu 2018/04/30
                     * ToDo: Judge which payload. @angelwhu 2018/04/30
                     */
                    public boolean checkDeserializationAttack(String stackTraceString)
                    {
                        for(String pattern : deserializationPattern)
                        {
                            if(stackTraceString.contains(pattern))
                            {
                                return true;
                            }
                        }
                        return false;
                    }

                    public void processDeserializationAttack(JudgeResult judgeResult)
                    {
                        String attackMessage = "";
                        attackMessage += "反序列化漏洞攻击";
                        judgeResult.setResultMessage(attackMessage);
                    }
                });
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("java.sql.Statement")
                /**/.includeBootstrap().includeSubClasses()
                .onBehavior("execute").onBehavior("executeUpdate").onBehavior("executeQuery")
                .onWatch(new AdviceListener() {
                    @Override
                    public void before(Advice advice) throws Throwable {
                        String sqlStatement = (String)advice.getParameterArray()[0];
                        System.out.println("SQL Statement:" + sqlStatement);
                        if(checkSQLInjection(sqlStatement))
                        {
                            /*
                            // Possible let server down. @angelwhu 2018/05/20
                            if(responseCache.get() !=null)
                            {
                                ResponseProcess responseProcess = new ResponseProcess(responseCache.get());
                                responseProcess.sendAlarmToViews("You are a good man~");
                            }
                            */
                            JudgeResult judgeResult = new JudgeResult();
                            judgeResult.setAttack(true);
                            judgeResult.setAttackType(JudgeResult.AttackType.SQLInjectAttack);
                            judgeResult.setRiskLevel(JudgeResult.RiskLevel.MEDIUM);
                            judgeResult.setResultMessage("SQL注入攻击：" + sqlStatement);

                            wrapMessageDataRef.get().storeMultilayerMessages();
                            judgeResult.processJudgeResult(wrapMessageDataRef.get(),StackTrace.getStackTrace());

                            /*
                            RuntimeException runtimeException = new RuntimeException("Block by rasp");
                            ProcessControlException.throwThrowsImmediately(runtimeException);
                            */
                            ProcessControlException.throwReturnImmediately(null);
                        }
                    }
                    public boolean checkSQLInjection(String sqlStatement)
                    {

                        String[] tokens = TokenGenerator.tokenize(sqlStatement, null);
                        Map<String, String[]> parameterMap = wrapMessageDataRef.get().getaHTTPServletLayerMessage().getHttpAccess().getParameterMap();
                        for(Map.Entry<String, String[]> entry : parameterMap.entrySet())
                        {
                            String[] values = entry.getValue();
                            for(String value : values)
                            {
                                if (!sqlStatement.contains(value))
                                {
                                    continue;
                                }
                                String[] tokens2 = TokenGenerator.tokenize(sqlStatement.replace(value,""));
                                if(tokens != null)
                                {
                                    if(tokens.length - tokens2.length > 1)
                                    {
                                        wrapMessageDataRef.get().getdBehaviorLayerMessage().setBehavior(DBehaviorLayerMessage.Behavior.queryDB);
                                        wrapMessageDataRef.get().getdBehaviorLayerMessage().setMessage("SQL注入，MapEntry:" + entry.getKey() + "===>" + value);
                                        return true;
                                    }
                                }
                            }
                        }
                        return false;
                    }
                });
    }

    public void buildExpressionWatcher()
    {
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("ognl.Ognl")
                /**/.includeBootstrap().includeSubClasses()
                .onBehavior("parseExpression") // before getValue or setValue, need to parseExpression first. @angelwhu 2018/04/24
                .onWatch(new AdviceListener() {
                    @Override
                    public void before(Advice advice) throws Throwable {

                        String ognlExpression = (String)advice.getParameterArray()[0];
                        if(ognlExpression.length() > 30) // ToDo: Add blacklist to filter expression. @angelwhu 2018/04/24
                        {
                            stLogger.info("Try to parse ognl Expression:" + ognlExpression);
                            if(wrapMessageDataRef.get() == null)
                            {
                                wrapMessageDataRef.set(new MultilayerMessageWrapper());
                            }
                            wrapMessageDataRef.get().getcExpressionLayerMessage().setLanguageType(CExpressionLayerMessage.LanguageType.OGNL);
                            wrapMessageDataRef.get().getcExpressionLayerMessage().setExpression(ognlExpression);
                        }
                    }
                });

        // Add struts2 OGNL expression cache. @angelwhu 2018/04/30
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("com.opensymphony.xwork2.ognl.OgnlUtil")
                /**/.includeBootstrap().includeSubClasses()
                .onBehavior("compileAndExecute") // before getValue or setValue, need to parseExpression first. @angelwhu 2018/04/24
                .onWatch(new AdviceListener() {
                    @Override
                    public void before(Advice advice) throws Throwable {
                        // Modify to hook set and get value.
                        String ognlExpression = (String)advice.getParameterArray()[0];
                        if(ognlExpression.length() > 30) // ToDo: Add blacklist to filter expression. @angelwhu 2018/04/24
                        {
                            stLogger.info("Xwork2 try to parse ognl Expression:" + ognlExpression);
                            if(wrapMessageDataRef.get() == null)
                            {
                                wrapMessageDataRef.set(new MultilayerMessageWrapper());
                            }
                            wrapMessageDataRef.get().getcExpressionLayerMessage().setLanguageType(CExpressionLayerMessage.LanguageType.OGNL);
                            wrapMessageDataRef.get().getcExpressionLayerMessage().setExpression(ognlExpression);
                        }
                    }
                });

        new EventWatchBuilder(moduleEventWatcher)
                .onClass("org.springframework.expression.ExpressionParser")
                /**/.includeBootstrap().includeSubClasses()
                .onBehavior("parseExpression") // before getValue or setValue, need to parseExpression first. @angelwhu 2018/04/24
                .onWatch(new AdviceListener() {
                    @Override
                    public void before(Advice advice) throws Throwable {
                        String spelExpression = (String)advice.getParameterArray()[0];
                        if(spelExpression.length() > 20)
                        {
                            stLogger.info("Try to parse SpEL Expression:" + spelExpression);
                            if(wrapMessageDataRef.get() == null)
                            {
                                wrapMessageDataRef.set(new MultilayerMessageWrapper());
                            }
                            wrapMessageDataRef.get().getcExpressionLayerMessage().setLanguageType(CExpressionLayerMessage.LanguageType.SpEL);
                            wrapMessageDataRef.get().getcExpressionLayerMessage().setExpression(spelExpression);
                        }
                    }
                });
    }

    public void buildApplicationWatcher()
    {
        /**
         * Struts2 mapping information. @angelwhu 2018/05/01
         */
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("org.apache.struts2.dispatcher.Dispatcher")
                /**/.includeBootstrap().includeSubClasses()
                .onBehavior("serviceAction")
                //.withParameterTypes("javax.servlet.http.HttpServletRequest","javax.servlet.http.HttpServletResponse","org.apache.struts2.dispatcher.mapper.ActionMapping")
                .onWatch(new AdviceListener(){
                    @Override
                    public void before(Advice advice) throws Throwable
                    {
                        //stLogger.info("serviceAction in Struts2.");
                        Object actionMapping = null;
                        if(advice.getParameterArray().length == 3)
                        {
                            actionMapping = advice.getParameterArray()[2];
                        }
                        else if(advice.getParameterArray().length == 4)  //Compatible with previous Struts2 versions.
                        {
                            actionMapping = advice.getParameterArray()[3];
                        }
                        else
                        {
                            return;
                        }

                        //String actionName = invokeMethod(actionMapping, "getName");
                        //String namespace = invokeMethod(actionMapping,"getNamespace");
                        //String method = invokeMethod(actionMapping,"getMethod");
                        //Map<String, Object> params = invokeMethod(actionMapping,"getParams");
                        //stLogger.info("Struts2 mapping:" + actionName + "," + namespace + "," + method);
                        stLogger.info("Struts2 mapping:" + invokeMethod(actionMapping,"toString"));

                        if(wrapMessageDataRef.get() == null)
                        {
                            wrapMessageDataRef.set(new MultilayerMessageWrapper());
                        }
                        wrapMessageDataRef.get().getbApplicationLayerMessage().setApplicationType(BApplicationLayerMessage.ApplicationType.struts2);
                        wrapMessageDataRef.get().getbApplicationLayerMessage().setMapping("" + invokeMethod(actionMapping,"toString"));
                        /**
                         * ToDo: Process parameters and results.
                         */
                    }
                });
        /**
         * Add springmvc mapping information. @angelwhu 2018/04/30
         */
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("org.springframework.web.servlet.HandlerAdapter")
                /**/.includeBootstrap().includeSubClasses()
                .onBehavior("handle")
                .onWatch(new AdviceListener(){
                    @Override
                    public void before(Advice advice) throws Throwable
                    {
                        stLogger.info("HandlerAdapter handle method in springmvc.");
                        Object handler = null;

                        handler = advice.getParameterArray()[2];

                        /**
                         * HandlerMethod: Got it~
                         * Controller: Todo~ @angelwhu 2018/04/30
                         * Servlet: Todo~ @angelwhu 2018/04/30
                         */

                        if(wrapMessageDataRef.get() == null)
                        {
                            wrapMessageDataRef.set(new MultilayerMessageWrapper());
                        }

                        Object method = FieldUtils.readField(handler,"method",true);
                        //String namespace = invokeMethod(actionMapping,"getNamespace");
                        //String method = invokeMethod(actionMapping,"getMethod");
                        //Map<String, Object> params = invokeMethod(actionMapping,"getParams");
                        //stLogger.info("Struts2 mapping:" + actionName + "," + namespace + "," + method);
                        stLogger.info("Springmvc mapping handler:" + invokeMethod(method,"toString"));
                        wrapMessageDataRef.get().getbApplicationLayerMessage().setApplicationType(BApplicationLayerMessage.ApplicationType.springmvc);
                        wrapMessageDataRef.get().getbApplicationLayerMessage().setMapping("" + invokeMethod(method,"toString"));
                        /**
                         * ToDo: Process parameters and results.
                         */
                    }
                });
    }

    public void buildHttpServletWatcher()
    {
        /**
         * Tomcat startup hook. @angelwhu 2018/05/21
         */
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("org.apache.catalina.startup.Catalina")
                .includeBootstrap()
                .onBehavior("start")
                .onWatch(new AdviceListener() {

                    final String MARK_VUL = "MARK_VUL";
                    @Override
                    public void before(Advice advice) throws Throwable {
                        if(checkCVE_2017_12615())
                        {
                            advice.mark(MARK_VUL);
                            if (wrapMessageDataRef.get()==null)
                            {
                                wrapMessageDataRef.set(new MultilayerMessageWrapper());
                            }
                            wrapMessageDataRef.get().getaHTTPServletLayerMessage().setHttpServerType(AHTTPServletLayerMessage.HttpServerType.tomcat);
                            wrapMessageDataRef.get().getaHTTPServletLayerMessage().setMessage("Tomcat可能存在CVE-2017-12615漏洞，请修改'conf/web.xml'配置文件。");
                            wrapMessageDataRef.get().storeMultilayerMessages();

                            JudgeResult judgeResult = new JudgeResult();
                            judgeResult.setAttack(true);
                            judgeResult.setRiskLevel(JudgeResult.RiskLevel.MEDIUM);
                            judgeResult.setAttackType(JudgeResult.AttackType.ServerConfigError);
                            judgeResult.setResultMessage("Tomcat可能存在配置漏洞，请查看各层次详细信息。");
                            judgeResult.processJudgeResult(wrapMessageDataRef.get(),StackTrace.getStackTrace());
                            /**
                             * ToDo: Elegant to stop server. @angelwhu 2018/05/21
                             */
                            RuntimeException securityException = new RuntimeException("Block by rasp");
                            ProcessControlException.throwThrowsImmediately(securityException);
                        }
                    }
                    @Override
                    public void afterReturning(Advice advice) throws Throwable {
                        // Shutdown server if it has vulnerabilities. @angelwhu 2018/05/21
                        if(advice.hasMark(MARK_VUL)) {
                            stLogger.info("Find vulnerability, stop server.");
                        }
                    }

                    public boolean checkCVE_2017_12615()
                    {
                        String tomcatBaseDir = System.getProperty("catalina.base");
                        File webXMLFile = new File(tomcatBaseDir + File.separator + "conf/web.xml");
                        if((!webXMLFile.exists())||(!webXMLFile.canRead()))
                        {
                            stLogger.info("Can not read conf/web.xml");
                        }

                        SAXReader reader = new SAXReader();
                        try {
                            Document document = reader.read(webXMLFile);
                            Element root = document.getRootElement();

                            for (Iterator<Element> it = root.elementIterator(); it.hasNext();)
                            {
                                Element servletElement = it.next();
                                if(servletElement.getName().equals("servlet"))
                                {
                                    for(Iterator<Element> it2 = servletElement.elementIterator();it2.hasNext();)
                                    {
                                        Element initParamElement = it2.next();
                                        if(initParamElement.getName().equals("init-param"))
                                        {
                                            String paramName = initParamElement.elementText("param-name");
                                            String paramValue = initParamElement.elementText("param-value");
                                            if(paramName.equals("readonly")&&paramValue.equals("false"))
                                            {
                                                return true;
                                            }
                                        }
                                    }

                                }
                            }
                        } catch (DocumentException e) {
                            e.printStackTrace();
                        }

                        return false;
                    }
                });


        /**
         * Get request parameters. Hook response, so that we can send error message to web views. @angelwhu 2018/04/30
         */

        new EventWatchBuilder(moduleEventWatcher)
                .onClass("org.apache.catalina.core.ApplicationFilterChain")
                .includeBootstrap()
                .onBehavior("doFilter")
                .onWatch(new AdviceListener() {
                    @Override
                    public void before(Advice advice) throws Throwable {

                        //stLogger.info("org.apache.catalina.core.ApplicationFilterChain enter. Length is:"+advice.getParameterArray().length);

                        if(wrapMessageDataRef.get() == null)
                        {
                            wrapMessageDataRef.set(new MultilayerMessageWrapper());
                        }
                        wrapMessageDataRef.get().getaHTTPServletLayerMessage().setHttpServerType(AHTTPServletLayerMessage.HttpServerType.tomcat);

                        final Object objectOfHttpServletRequest = advice.getParameterArray()[0];
                        final AHTTPServletLayerMessage.AHttpAccess ha = wrapMessageDataRef.get().getaHTTPServletLayerMessage().getHttpAccess();
                        ha.setFrom((String)invokeMethod(objectOfHttpServletRequest, "getRemoteAddr"));
                        ha.setMethod((String)invokeMethod(objectOfHttpServletRequest, "getMethod"));
                        ha.setUri((String) invokeMethod(objectOfHttpServletRequest, "getRequestURI"));
                        ha.setParameterMap((Map<String, String[]>) invokeMethod(objectOfHttpServletRequest, "getParameterMap"));
                        ha.setUserAgent((String) invokeMethod(objectOfHttpServletRequest, "getHeader", "User-Agent"));
                        ha.setCookie((String) invokeMethod(objectOfHttpServletRequest, "getHeader", "Cookie"));
                        ha.setBeginTimestamp(System.currentTimeMillis());

                        /**
                         * ToDo: Get post data. Need to consider performance. @angelwhu 2018/04/30
                         */

                        responseCache.set(advice.getParameterArray()[1]); // Hook response to send error~ @angelwhu 2018/04/26

                    }

                    /**
                     * Hook exit thread, to clear threadlocal. @angelwhu 2018/05/14
                     */
                    @Override
                    public void afterThrowing(Advice advice) throws Throwable {
                        stLogger.info("org.apache.catalina.core.ApplicationFilterChain,doFilter,afterThrowing");
                        wrapMessageDataRef.set(null);
                        responseCache.set(null);
                    }

                    @Override
                    public void afterReturning(Advice advice) throws Throwable {
                        stLogger.info("org.apache.catalina.core.ApplicationFilterChain,doFilter,afterReturning");
                        wrapMessageDataRef.set(null);
                        responseCache.set(null);
                    }

                });


        /**
         * Jetty
         */
        new EventWatchBuilder(moduleEventWatcher)
                .onClass("org.eclipse.jetty.server.handler.HandlerWrapper")
                .includeBootstrap()
                .onBehavior("handle")
                .onWatch(new AdviceListener() {
                    @Override
                    public void before(Advice advice) throws Throwable {

                        stLogger.info("org.eclipse.jetty.server.handler.HandlerWrapper.handle. Length is:"+advice.getParameterArray().length);
                        for(Object object : advice.getParameterArray())
                        {
                            stLogger.info(object.getClass().toString()+"\n");
                        }
                        if(wrapMessageDataRef.get() == null)
                        {
                            wrapMessageDataRef.set(new MultilayerMessageWrapper());
                        }
                        wrapMessageDataRef.get().getaHTTPServletLayerMessage().setHttpServerType(AHTTPServletLayerMessage.HttpServerType.jetty);

                        final Object objectOfHttpServletRequest = advice.getParameterArray()[2];
                        final AHTTPServletLayerMessage.AHttpAccess ha = wrapMessageDataRef.get().getaHTTPServletLayerMessage().getHttpAccess();
                        ha.setFrom((String)invokeMethod(objectOfHttpServletRequest, "getRemoteAddr"));
                        ha.setMethod((String)invokeMethod(objectOfHttpServletRequest, "getMethod"));
                        ha.setUri((String) invokeMethod(objectOfHttpServletRequest, "getRequestURI"));
                        ha.setParameterMap((Map<String, String[]>) invokeMethod(objectOfHttpServletRequest, "getParameterMap"));
                        ha.setUserAgent((String) invokeMethod(objectOfHttpServletRequest, "getHeader", "User-Agent"));
                        ha.setCookie((String) invokeMethod(objectOfHttpServletRequest, "getHeader", "Cookie"));
                        ha.setBeginTimestamp(System.currentTimeMillis());
                        stLogger.info(JSON.toJSONString(ha));
                        /**
                         * ToDo: Get post data. Need to consider performance. @angelwhu 2018/04/30
                         */

                        responseCache.set(advice.getParameterArray()[3]); // Hook response to send error~ @angelwhu 2018/04/26

                    }

                    /**
                     * Hook exit thread, to clear threadlocal. @angelwhu 2018/05/14
                     */
                    @Override
                    public void afterThrowing(Advice advice) throws Throwable {

                        wrapMessageDataRef.set(null);
                        responseCache.set(null);
                    }

                    @Override
                    public void afterReturning(Advice advice) throws Throwable {
                        wrapMessageDataRef.set(null);
                        responseCache.set(null);
                    }

                });
    }


    /*
     * 泛型转换方法调用
     * 底层使用apache common实现
     */
    private static <T> T invokeMethod(final Object object,
                                      final String methodName,
                                      final Object... args) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        return (T) MethodUtils.invokeMethod(object, methodName, args);
    }

}
