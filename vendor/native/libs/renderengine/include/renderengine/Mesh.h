/*
 * Copyright 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SF_RENDER_ENGINE_MESH_H
#define SF_RENDER_ENGINE_MESH_H

#include <vector>

#include <stdint.h>

namespace android {
namespace renderengine {

class Mesh {
public:
    class Builder;

    enum Primitive {
        TRIANGLES = 0x0004,      // GL_TRIANGLES
        TRIANGLE_STRIP = 0x0005, // GL_TRIANGLE_STRIP
        TRIANGLE_FAN = 0x0006    // GL_TRIANGLE_FAN
    };

    ~Mesh() = default;

    /*
     * VertexArray handles the stride automatically.
     */
    template <typename TYPE>
    class VertexArray {
        friend class Mesh;
        float* mData;
        size_t mStride;
        size_t mOffset = 0;
        VertexArray(float* data, size_t stride) : mData(data), mStride(stride) {}

    public:
        // Returns a vertex array at an offset so its easier to append attributes from
        // multiple sources.
        VertexArray(VertexArray<TYPE>& other, size_t offset)
              : mData(other.mData), mStride(other.mStride), mOffset(offset) {}

        TYPE& operator[](size_t index) {
            return *reinterpret_cast<TYPE*>(&mData[(index + mOffset) * mStride]);
        }
        TYPE const& operator[](size_t index) const {
            return *reinterpret_cast<TYPE const*>(&mData[(index + mOffset) * mStride]);
        }
    };

    template <typename TYPE>
    VertexArray<TYPE> getPositionArray() {
        return VertexArray<TYPE>(getPositions(), mStride);
    }

    template <typename TYPE>
    VertexArray<TYPE> getTexCoordArray() {
        return VertexArray<TYPE>(getTexCoords(), mStride);
    }

    template <typename TYPE>
    VertexArray<TYPE> getCropCoordArray() {
        return VertexArray<TYPE>(getCropCoords(), mStride);
    }

    template <typename TYPE>
    VertexArray<TYPE> getShadowColorArray() {
        return VertexArray<TYPE>(getShadowColor(), mStride);
    }

    template <typename TYPE>
    VertexArray<TYPE> getShadowParamsArray() {
        return VertexArray<TYPE>(getShadowParams(), mStride);
    }

    uint16_t* getIndicesArray() { return getIndices(); }

    Primitive getPrimitive() const;

    // returns a pointer to the vertices positions
    float const* getPositions() const;

    // returns a pointer to the vertices texture coordinates
    float const* getTexCoords() const;

    // returns a pointer to the vertices crop coordinates
    float const* getCropCoords() const;

    // returns a pointer to colors
    float const* getShadowColor() const;

    // returns a pointer to the shadow params
    float const* getShadowParams() const;

    // returns a pointer to indices
    uint16_t const* getIndices() const;

    // number of vertices in this mesh
    size_t getVertexCount() const;

    // dimension of vertices
    size_t getVertexSize() const;

    // dimension of texture coordinates
    size_t getTexCoordsSize() const;

    size_t getShadowParamsSize() const;

    size_t getShadowColorSize() const;

    size_t getIndexCount() const;

    // return stride in bytes
    size_t getByteStride() const;

    // return stride in floats
    size_t getStride() const;

private:
    Mesh(Primitive primitive, size_t vertexCount, size_t vertexSize, size_t texCoordSize,
         size_t cropCoordsSize, size_t shadowColorSize, size_t shadowParamsSize, size_t indexCount);
    Mesh(const Mesh&);
    Mesh& operator=(const Mesh&);
    Mesh const& operator=(const Mesh&) const;

    float* getPositions();
    float* getTexCoords();
    float* getCropCoords();
    float* getShadowColor();
    float* getShadowParams();
    uint16_t* getIndices();

    std::vector<float> mVertices;
    size_t mVertexCount;
    size_t mVertexSize;
    size_t mTexCoordsSize;
    size_t mCropCoordsSize;
    size_t mShadowColorSize;
    size_t mShadowParamsSize;
    size_t mStride;
    Primitive mPrimitive;
    std::vector<uint16_t> mIndices;
    size_t mIndexCount;
};

class Mesh::Builder {
public:
    Builder& setPrimitive(Primitive primitive) {
        mPrimitive = primitive;
        return *this;
    };
    Builder& setVertices(size_t vertexCount, size_t vertexSize) {
        mVertexCount = vertexCount;
        mVertexSize = vertexSize;
        return *this;
    };
    Builder& setTexCoords(size_t texCoordsSize) {
        mTexCoordsSize = texCoordsSize;
        return *this;
    };
    Builder& setCropCoords(size_t cropCoordsSize) {
        mCropCoordsSize = cropCoordsSize;
        return *this;
    };
    Builder& setShadowAttrs() {
        mShadowParamsSize = 3;
        mShadowColorSize = 4;
        return *this;
    };
    Builder& setIndices(size_t indexCount) {
        mIndexCount = indexCount;
        return *this;
    };
    Mesh build() const {
        return Mesh{mPrimitive,      mVertexCount,     mVertexSize,       mTexCoordsSize,
                    mCropCoordsSize, mShadowColorSize, mShadowParamsSize, mIndexCount};
    }

private:
    size_t mVertexCount = 0;
    size_t mVertexSize = 0;
    size_t mTexCoordsSize = 0;
    size_t mCropCoordsSize = 0;
    size_t mShadowColorSize = 0;
    size_t mShadowParamsSize = 0;
    size_t mIndexCount = 0;
    Primitive mPrimitive;
};

} // namespace renderengine
} // namespace android
#endif /* SF_RENDER_ENGINE_MESH_H */
