int fooo() {
    int a = 0;
    a += 2;
    a /= 2;
    a++;
    a++;
    a /= 3;
    return a;
}

int barr() {
    int a = 0;
    a += 2;
    a /= 2;
    a++;
    a++;
    a /= 1;
    return a;
}

int main() {
    int a = fooo();
    int b = barr();
    int c = b - a;
    c -= a;
    c -= a;
    return c;
}
