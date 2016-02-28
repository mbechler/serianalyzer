/**
 *   This file is part of Serianalyzer.
 *
 *   Serianalyzer is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   Serianalyzer is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with Serianalyzer.  If not, see <http://www.gnu.org/licenses/>.
 *   
 * Copyright 2015,2016 Moritz Bechler <mbechler@eenterphace.org>
 * 
 * Created: 19.11.2015 by mbechler
 */
package serianalyzer;


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
