char toto()
{
    volatile unsigned char buffer[4096];
    buffer[0] = 1;
    buffer[4095] = 0;
    toto();
    return buffer[0] + buffer[sizeof(buffer)-1];
}

int main()
{
    char c = toto();
    return c;
}
