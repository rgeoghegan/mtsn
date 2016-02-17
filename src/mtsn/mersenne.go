package mtsn

const (
    w uint32 = 32
    n uint32 = 624
    m uint32 = 397
    r uint32 = 31

    a uint32 = 0x9908B0DF

    u uint32 = 11
    d uint32 = 0xFFFFFFFF

    s uint32 = 7
    b uint32 = 0x9D2C5680
    t uint32 = 15
    c uint32 = 0xEFC60000

    l uint32 = 18
    f uint32 = 0x6c078965
    upperMask uint32 = 0x80000000
    lowerMask uint32 = 0x7fffffff
)

type GeneratorState struct {
    Mt [n]uint32
    Index uint32
}

func Generator(seed uint32) *GeneratorState {
    state := new(GeneratorState)
    state.Mt[0] = seed
    for i := uint32(1); i < n; i++ {
        state.Mt[i] = f * (state.Mt[i-1] ^ (state.Mt[i-1] >> (w - 2))) + i
    }
    state.Index = n

    return state
}

func (g *GeneratorState) Twist() {
    for i, v := range g.Mt {
        iu := uint32(i)
        x := (v & upperMask) + (g.Mt[(iu + 1) % n] & lowerMask)
        xA := x >> 1

        if (x % 2) == 1 {
            xA = xA ^ a
        }
        g.Mt[i] = g.Mt[(iu + m) % n] ^ xA
    }
    g.Index = 0
}

func (g *GeneratorState) Extract() uint32 {
    if g.Index >= n {
        g.Twist()
    }

    y := g.Mt[g.Index]
    y = y ^ ((y >> u) & d)
    y = y ^ ((y << s) & b)
    y = y ^ ((y << t) & c)
    y = y ^ (y >> l)

    g.Index++

    return y
}

/*

let unextract x =
    (* Gets the inital value fed into extract_number *)
    let mask size offset =
        ((1 lsl size) - 1) lsl offset
    in
    let extract_block_left y block shift ander offset =
        let mask = ((1 lsl shift) - 1) lsl offset
        in
        (((block lsl shift) land ander) lxor y) land mask
    in

    let extract_all_left y shift ander =
        let rec iter offset block =
            if offset > 32
            then block
            else iter
                (offset + shift)
                (block lxor (extract_block_left y block shift ander offset))
        in
        iter shift (y land ((1 lsl shift) - 1))
    in
    (* Step 4 *)
    let y = x lxor (x lsr l) in

    (* Step 3 *)
    let y = extract_all_left y t c in

    (* Step 2 *)
    let y = extract_all_left y s b in

    (* Step 1 *)
    let p1 = y land (mask u (32 - u)) in
    let p2 = (y lxor (p1 lsr u)) land
        (mask u (32 - u - u)) in
    let p3 = (y lxor (p2 lsr u)) land (mask 10 0) in

    p1 lor p2 lor p3
;;
*/

func mask(size uint32, offset uint32) uint32 {
    return ((uint32(1) << size) - uint32(1)) << offset
}

func extractBlockLeft(y uint32, block uint32, shift uint32, ander uint32, offset uint32) uint32{
    maskV := mask(shift, offset)
    return (((block << shift) & ander) ^ y) & maskV
}

func extractAllLeft(y uint32, shift uint32, ander uint32) uint32 {
    block := y & ((1 << shift) - 1)
    for i := shift; i < 33; i += shift {
        block = block ^ extractBlockLeft(y, block, shift, ander, i)
    }
    return block
}

func Unextract(x uint32) uint32 {
    // Gets the inital value fed into extract_number
    // Step 4
    y := x ^ (x >> l)
    // Step 3
    y = extractAllLeft(y, t, c)
    // Step 2
    y = extractAllLeft(y, s, b)

    // Step 1
    p1 := y & mask(u, 32 - u)
    p2 := (y ^ (p1 >> u)) & mask(u, 32 - u - u)
    p3 := (y ^ (p2 >> u)) & mask(10, 0)
    
    return p1 | p2 | p3
}
