/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 16.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import javax.activation.DataSource;
import javax.activation.URLDataSource;

import org.apache.log4j.Logger;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.Index;
import org.jboss.jandex.Indexer;


/**
 * @author mbechler
 */
public class SerianalyzerInput {

    private static final Logger log = Logger.getLogger(SerianalyzerInput.class);

    /**
     * 
     */
    private SerianalyzerConfig config;
    /**
     * 
     */
    private Indexer indexer = new Indexer();
    /**
     * 
     */
    private Map<String, DataSource> classData = new HashMap<>();
    /**
     * 
     */
    private Index index;


    /**
     * @param cfg
     * 
     */
    public SerianalyzerInput ( SerianalyzerConfig cfg ) {
        this.config = cfg;
    }


    /**
     * @return the config
     */
    public SerianalyzerConfig getConfig () {
        return this.config;
    }


    /**
     * @return the index
     */
    public Index getIndex () {
        if ( this.index == null ) {
            this.index = this.indexer.complete();
        }
        return this.index;
    }


    /**
     * 
     * @param jarFile
     * @throws IOException
     */
    public void index ( File jarFile ) throws IOException {
        log.debug("Indexing file " + jarFile); //$NON-NLS-1$
        @SuppressWarnings ( "resource" )
        JarFile jar = new JarFile(jarFile);
        Enumeration<JarEntry> entries = jar.entries();
        while ( entries.hasMoreElements() ) {
            JarEntry entry = entries.nextElement();
            if ( entry.getName().endsWith(".class") ) { //$NON-NLS-1$
                index(new JARDataSource(jar, entry));
            }
            else if ( entry.getName().endsWith(".jar") ) { //$NON-NLS-1$
                log.error("Nested JARs not yet supported " + entry.getName()); //$NON-NLS-1$
            }
        }
    }


    /**
     * 
     * @param u
     * @throws IOException
     */
    public void index ( URL u ) throws IOException {
        try ( InputStream openStream = u.openStream() ) {
            index(new URLDataSource(u));
        }
    }


    /**
     * 
     * @param source
     * @throws IOException
     */
    public void index ( DataSource source ) throws IOException {
        ClassInfo ci = this.indexer.index(source.getInputStream());
        if ( this.classData.put(ci.name().toString(), new ByteDataSource(source)) != null ) {
            log.warn("Duplicate class " + ci.name()); //$NON-NLS-1$
        }
    }


    /**
     * @param p
     * @throws IOException
     */
    public void index ( Path p ) throws IOException {
        if ( Files.isDirectory(p) ) {
            Files.find(p, 10, ( t, u ) -> t.getFileName().toString().endsWith(".jar")).forEach(r -> { //$NON-NLS-1$
                    try {
                        index(r.toFile());
                    }
                    catch ( IOException e ) {
                        log.error("Failed to open file " + r, e); //$NON-NLS-1$
                    }
                });
        }
        else {
            try {
                index(p.toFile());
            }
            catch ( IOException e ) {
                log.error("Failed to open file " + p, e); //$NON-NLS-1$
            }
        }
    }


    /**
     * @param typeName
     * @return class bytecode data
     * @throws IOException
     */
    public InputStream getClassData ( String typeName ) throws IOException {
        DataSource data = this.classData.get(typeName);
        if ( data == null ) {
            return null;
        }
        return data.getInputStream();
    }
}