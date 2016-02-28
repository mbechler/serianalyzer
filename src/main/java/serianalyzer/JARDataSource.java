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
