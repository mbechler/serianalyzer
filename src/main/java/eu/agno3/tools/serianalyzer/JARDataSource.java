/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 19.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

import javax.activation.DataSource;


/**
 * @author mbechler
 *
 */
public class JARDataSource implements DataSource {

    private JarFile jarFile;
    private ZipEntry entry;


    /**
     * @param jarFile
     * @param entry
     */
    public JARDataSource ( JarFile jarFile, ZipEntry entry ) {
        this.jarFile = jarFile;
        this.entry = entry;
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getContentType()
     */
    @Override
    public String getContentType () {
        throw new UnsupportedOperationException();
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getInputStream()
     */
    @Override
    public InputStream getInputStream () throws IOException {
        return this.jarFile.getInputStream(this.entry);
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getName()
     */
    @Override
    public String getName () {
        return this.entry.getName();
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getOutputStream()
     */
    @Override
    public OutputStream getOutputStream () throws IOException {
        throw new UnsupportedOperationException();
    }

}
