/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 16.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
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

import org.apache.log4j.Logger;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.DotName;
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
    private Map<DotName, byte[]> classData = new HashMap<>();
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
        log.debug("Indexing " + jarFile); //$NON-NLS-1$
        try ( JarFile jar = new JarFile(jarFile) ) {
            Enumeration<JarEntry> entries = jar.entries();
            while ( entries.hasMoreElements() ) {
                JarEntry entry = entries.nextElement();
                if ( entry.getName().endsWith(".class") ) { //$NON-NLS-1$
                    try ( InputStream stream = jar.getInputStream(entry) ) {
                        index(stream);
                    }
                    catch ( IOException e ) {
                        log.error("Failed to index class file " + entry.getName() + " in " + jarFile, e); //$NON-NLS-1$ //$NON-NLS-2$
                    }
                }
                else if ( entry.getName().endsWith(".jar") ) { //$NON-NLS-1$
                    log.error("Nested JARs not yet supported " + entry.getName()); //$NON-NLS-1$
                }
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
            index(openStream);
        }
    }


    /**
     * 
     * @param is
     * @throws IOException
     */
    public void index ( InputStream is ) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        byte[] buffer = new byte[4096];
        int read = 0;

        while ( ( read = is.read(buffer) ) >= 0 ) {
            bos.write(buffer, 0, read);
        }

        ClassInfo ci = this.indexer.index(new ByteArrayInputStream(bos.toByteArray()));
        if ( this.classData.put(ci.name(), bos.toByteArray()) != null ) {
            log.warn("Duplicate class " + ci.name()); //$NON-NLS-1$
        }
    }


    /**
     * @param p
     * @throws IOException
     */
    public void index ( Path p ) throws IOException {
        if ( Files.isDirectory(p) ) {
            Files.find(p, 5, ( t, u ) -> t.getFileName().toString().endsWith(".jar")).forEach(r -> { //$NON-NLS-1$
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
     */
    public InputStream getClassData ( DotName typeName ) {
        byte[] data = this.classData.get(typeName);
        if ( data == null ) {
            return null;
        }
        return new ByteArrayInputStream(data);
    }
}