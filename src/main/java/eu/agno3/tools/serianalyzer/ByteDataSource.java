/**
 * © 2015 AgNO3 Gmbh & Co. KG
 * All right reserved.
 * 
 * Created: 19.11.2015 by mbechler
 */
package eu.agno3.tools.serianalyzer;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.activation.DataSource;


/**
 * @author mbechler
 *
 */
public class ByteDataSource implements DataSource {

    private byte[] data;


    /**
     * @param ds
     * @throws IOException
     */
    public ByteDataSource ( DataSource ds ) throws IOException {
        try ( InputStream is = ds.getInputStream() ) {
            int read;
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte buffer[] = new byte[4096];
            while ( ( read = is.read(buffer) ) > 0 ) {
                bos.write(buffer, 0, read);
            }
            this.data = bos.toByteArray();
        }
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getContentType()
     */
    @Override
    public String getContentType () {
        // TODO Auto-generated method stub
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getInputStream()
     */
    @Override
    public InputStream getInputStream () throws IOException {
        return new ByteArrayInputStream(this.data);
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getName()
     */
    @Override
    public String getName () {
        // TODO Auto-generated method stub
        return null;
    }


    /**
     * {@inheritDoc}
     *
     * @see javax.activation.DataSource#getOutputStream()
     */
    @Override
    public OutputStream getOutputStream () throws IOException {
        // TODO Auto-generated method stub
        return null;
    }

}
